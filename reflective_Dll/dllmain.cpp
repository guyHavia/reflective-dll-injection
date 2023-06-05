// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "reflectiveDll.h"


EXTERN_C __declspec(dllexport) DWORD test(DWORD number)
{
    MessageBoxA(NULL, "test function", "exported function", MB_OK);
    return 0;
}

// table of content:
// 1. find base address of process 
// 2. parse peb & extract all winAPI functions from kernel32, ntdll
// 3. allocate memory for real dll
// 4. resolve headers & sections
// 5. load dll dependencies (from dll import table)
// 6. relocations
// 7. start dllmain function

HINSTANCE hAppInstance = NULL;
#pragma intrinsic( _ReturnAddress )
__declspec(noinline) ULONG_PTR caller(VOID) { return (ULONG_PTR)_ReturnAddress(); }

EXTERN_C __declspec(dllexport) DWORD self_loader()
{
    // variables for find victim process base address
    ULONG_PTR raw_dll_base_address, raw_dll_nt_header;

    // variables for parse PEB
    ULONG_PTR peb_address;
    ULONG_PTR peb_ldr_data;
    ULONG_PTR list_head;
    ULONG_PTR list_next;
    ULONG_PTR ldr_entry;
    ULONG_PTR dll_name;
    WORD module_value;

    // Variables for extract functions from kernel32.dll / ntdll.dll
    ULONG_PTR module_base_address;
    PIMAGE_DOS_HEADER dos_header;
    PIMAGE_NT_HEADERS nt_header;
    PIMAGE_EXPORT_DIRECTORY export_directory;
    ULONG_PTR exported_functions_names_array, exported_functions_addresses_array, exported_functions_ordinal_array, function_address;
    DWORD module_counter = 0;
    char* exported_function;
    WORD function_value;

    // Variables for using functions
    LoadLibraryA_Func loadLibrary_func = NULL;
    GetProcAddress_Func getProcAddress_func = NULL;
    VirtualAlloc_Func virtualAlloc_func = NULL;
    FlushInstructionCache_Func flushInstructionCache_func = NULL;

    // Variables for allocating the dll to new location
    ULONG_PTR new_base_address, new_base_address_copy, size_of_headers, raw_dll_base_address_copy, number_of_sections;
    ULONG_PTR size_to_allocate, first_section_address, new_section_virtual_address, new_section_pointer_raw, new_size_of_section;

    // Variables for resolving import table
    ULONG_PTR imported_dll_list, imported_dll_entry, imported_dll_name, imported_name_table_pointer, imported_address_table_pointer, exported_dll_nt_header;
    ULONG_PTR exported_dll_export_descriptor, uiExportdir;

    // variables for relocations
    ULONG_PTR delta, base_relocations_dir, relocation_entry, number_of_entries, reloc_va ,uiValueD;

    // variables for start mainDLL
    ULONG_PTR entry_point;


    // Find base address of victim process
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    raw_dll_base_address = caller();
    // loop through memory backwards searching for our images base address
    while (TRUE)
    {
        if (((PIMAGE_DOS_HEADER)raw_dll_base_address)->e_magic == IMAGE_DOS_SIGNATURE)
        {
            raw_dll_nt_header = ((PIMAGE_DOS_HEADER)raw_dll_base_address)->e_lfanew;
            // some x64 dll's can trigger a bogus signature (IMAGE_DOS_SIGNATURE == 'POP r10'),
            // we sanity check the e_lfanew with an upper threshold value of 1024 to avoid problems.
            if (raw_dll_nt_header >= sizeof(IMAGE_DOS_HEADER) && raw_dll_nt_header < 1024)
            {
                raw_dll_nt_header += raw_dll_base_address;
                // break if we have found a valid MZ/PE header
                if (((PIMAGE_NT_HEADERS)raw_dll_nt_header)->Signature == IMAGE_NT_SIGNATURE)
                    break;
            }
        }
        raw_dll_base_address--;
    }
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


    // Parse PEB structure && get needed Exported functions - finished!
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#if _WIN64
    peb_address = __readgsqword(0x60);
#else
    _asm
    {
        xor eax, eax;
        mov eax, fs: [0x30] ;
        mov[peb_address], eax;
    }
#endif

    peb_ldr_data = (ULONG_PTR)((_PPEB)peb_address)->pLdr;
    list_head = (ULONG_PTR)((PPEB_LDR_DATA)peb_ldr_data)->InMemoryOrderModuleList.Flink;

    while (module_counter < 3)
    {
        //ldr_entry = (LDR_DATA_TABLE_ENTRY_COMPLETED*)((char*)list_next - sizeof(LIST_ENTRY));
        dll_name = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)list_head)->BaseDllName.pBuffer;
        module_value = module_calc((wchar_t*)dll_name);
        if (module_value == KERNEL32)
        {
            module_base_address = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)list_head)->DllBase;
            dos_header = (PIMAGE_DOS_HEADER)module_base_address;
            nt_header = (PIMAGE_NT_HEADERS)(module_base_address + dos_header->e_lfanew);
            export_directory = (PIMAGE_EXPORT_DIRECTORY)(module_base_address + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
            exported_functions_names_array = (module_base_address + export_directory->AddressOfNames);
            exported_functions_addresses_array = (module_base_address + export_directory->AddressOfFunctions);
            exported_functions_ordinal_array = (module_base_address + export_directory->AddressOfNameOrdinals);
        
            // run untill we found all addresses
            while (!loadLibrary_func || !getProcAddress_func || !virtualAlloc_func)
            {

                exported_function = (char*)(module_base_address + *(DWORD*)exported_functions_names_array);
                // get va of addressOfFunctions Array
                function_address = (module_base_address + ((PIMAGE_EXPORT_DIRECTORY)export_directory)->AddressOfFunctions);
                // add the value store in ordinal * dword
                function_address += (*(WORD*)exported_functions_ordinal_array) * sizeof(DWORD);
                function_value = function_calc(exported_function);

                if (function_value == LoadLibraryA_Value)
                {
                    loadLibrary_func = (LoadLibraryA_Func)(module_base_address + (*(DWORD*)function_address));
                }
                else if (function_value == GetProcAddress_Value)
                {
                    getProcAddress_func = (GetProcAddress_Func)(module_base_address + (*(DWORD*)function_address));
                }
                else if (function_value == VirtualAlloc_Value)
                {
                    virtualAlloc_func = (VirtualAlloc_Func)(module_base_address + (*(DWORD*)function_address));
                }
                // move to next function
                exported_functions_names_array += sizeof(DWORD);
                exported_functions_ordinal_array += sizeof(WORD);
            }
        }
        if (module_value == NTDLL)
        {
            module_base_address = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)list_head)->DllBase;
            dos_header = (PIMAGE_DOS_HEADER)module_base_address;
            nt_header = (PIMAGE_NT_HEADERS)(module_base_address + dos_header->e_lfanew);
            export_directory = (PIMAGE_EXPORT_DIRECTORY)(module_base_address + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
            exported_functions_names_array = (module_base_address + export_directory->AddressOfNames);
            exported_functions_addresses_array = (module_base_address + export_directory->AddressOfFunctions);
            exported_functions_ordinal_array = (module_base_address + export_directory->AddressOfNameOrdinals);

            // run untill we found all addresses
            while (!flushInstructionCache_func)
            {
                exported_function = (char*)(module_base_address + *(DWORD*)exported_functions_names_array);
                // get va of addressOfFunctions Array
                function_address = (module_base_address + ((PIMAGE_EXPORT_DIRECTORY)export_directory)->AddressOfFunctions);
                // add the value store in ordinal * dword
                function_address += (*(WORD*)exported_functions_ordinal_array) * sizeof(DWORD);
                function_value = function_calc(exported_function);
                
                if (function_value == FlushInstructionCache_Value)
                {
                    // Address = base + base address array + ordinal Number * dword (size of each value in address list)
                    flushInstructionCache_func = (FlushInstructionCache_Func)(module_base_address + (*(DWORD*)function_address));
                }
                // move to next function
                exported_functions_names_array += sizeof(DWORD);
                exported_functions_ordinal_array += sizeof(WORD);
            }
        }
        // continue to next module
        list_head = *(UINT_PTR*)list_head;
        module_counter++;   
    }
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


    // Load image to new permanent location & relocate sections and headers
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    raw_dll_nt_header = raw_dll_base_address + ((PIMAGE_DOS_HEADER)raw_dll_base_address)->e_lfanew;

    // allocate the new space
    new_base_address = (ULONG_PTR)virtualAlloc_func(NULL, ((PIMAGE_NT_HEADERS)raw_dll_nt_header)->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!new_base_address)
    {
        return 0;
    }
    // move all the sections tp new location
    size_of_headers = ((PIMAGE_NT_HEADERS)raw_dll_nt_header)->OptionalHeader.SizeOfHeaders;
    raw_dll_base_address_copy = raw_dll_base_address;
    new_base_address_copy = new_base_address;

    while (size_of_headers--)
        // copy all the headers to new location
        *(BYTE*)new_base_address_copy++ = *(BYTE*)raw_dll_base_address_copy++;

    // Copy sections
    first_section_address = ((ULONG_PTR) & ((PIMAGE_NT_HEADERS)raw_dll_nt_header)->OptionalHeader + ((PIMAGE_NT_HEADERS)raw_dll_nt_header)->FileHeader.SizeOfOptionalHeader);
    number_of_sections = ((PIMAGE_NT_HEADERS)raw_dll_nt_header)->FileHeader.NumberOfSections;

    // iterate through all the sections
    while (number_of_sections--)
    { 
        // get addresses of new location dll
        new_section_virtual_address = new_base_address + ((PIMAGE_SECTION_HEADER)first_section_address)->VirtualAddress;
        new_section_pointer_raw = raw_dll_base_address + ((PIMAGE_SECTION_HEADER)first_section_address)->PointerToRawData;
        new_size_of_section = ((PIMAGE_SECTION_HEADER)first_section_address)->SizeOfRawData;

        // Copy all section data byte after byte
        while (new_size_of_section--)
            *(BYTE*)new_section_virtual_address++ = *(BYTE*)new_section_pointer_raw++;

        // get address of next section
        first_section_address += sizeof(IMAGE_SECTION_HEADER);
    }   
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // Resolve imports of new allocated DLL
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    ULONG_PTR new_nt_header = new_base_address + ((PIMAGE_DOS_HEADER)new_base_address)->e_lfanew;

    // change to raw_nt_header
    imported_dll_list = (ULONG_PTR)&((PIMAGE_NT_HEADERS)new_nt_header)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    imported_dll_entry = (new_base_address + ((PIMAGE_DATA_DIRECTORY)imported_dll_list)->VirtualAddress);

    // run on every imported DLL
    while ( ((PIMAGE_IMPORT_DESCRIPTOR)imported_dll_entry)->Name )
    {
        // change all raw to new_base_address
        imported_dll_name = (ULONG_PTR)loadLibrary_func((LPSTR)(new_base_address + ((PIMAGE_IMPORT_DESCRIPTOR)imported_dll_entry)->Name));
        //std::cout << imported_dll_name << std::endl;
        imported_name_table_pointer = (new_base_address + ((PIMAGE_IMPORT_DESCRIPTOR)imported_dll_entry)->OriginalFirstThunk);
        imported_address_table_pointer = (new_base_address + ((PIMAGE_IMPORT_DESCRIPTOR)imported_dll_entry)->FirstThunk);
        
        // run on every dll function
        while (*(UINT_PTR*)(imported_address_table_pointer))
        {
            // resolve imports by ordinal
            if (imported_name_table_pointer && ((PIMAGE_THUNK_DATA)imported_name_table_pointer)->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                exported_dll_nt_header = imported_dll_name + ((PIMAGE_DOS_HEADER)imported_dll_name)->e_lfanew;
                exported_dll_export_descriptor = (ULONG_PTR)&((PIMAGE_NT_HEADERS)exported_dll_nt_header)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                uiExportdir = (imported_dll_name + ((PIMAGE_DATA_DIRECTORY)exported_dll_export_descriptor)->VirtualAddress);
                exported_functions_names_array = imported_dll_name + ((PIMAGE_EXPORT_DIRECTORY)uiExportdir)->AddressOfNames;
                exported_functions_addresses_array = imported_dll_name + ((PIMAGE_EXPORT_DIRECTORY)uiExportdir)->AddressOfFunctions;
                exported_functions_addresses_array += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)imported_name_table_pointer)->u1.Ordinal) - ((PIMAGE_EXPORT_DIRECTORY)uiExportdir)->Base) * sizeof(DWORD));
                *(UINT_PTR*)(imported_dll_list) = (imported_dll_name + *(DWORD*)exported_functions_addresses_array);
            }
            else
            { 
                imported_dll_list = (new_base_address + *(UINT_PTR*)(imported_address_table_pointer));
                *(UINT_PTR*)(imported_address_table_pointer) = (ULONG_PTR)getProcAddress_func((HMODULE)imported_dll_name, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)imported_dll_list)->Name);
            }
            imported_address_table_pointer += sizeof(ULONG_PTR);
            if (imported_name_table_pointer)
            {
                imported_name_table_pointer += sizeof(ULONG_PTR);
            }
        }
        // skip to the next dll in list
        imported_dll_entry += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    //Relocations
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    delta = new_base_address - ((PIMAGE_NT_HEADERS)new_nt_header)->OptionalHeader.ImageBase;
    base_relocations_dir = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)new_nt_header)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if ( ((PIMAGE_DATA_DIRECTORY)base_relocations_dir)->Size )
    {
        relocation_entry = (new_base_address + ((PIMAGE_BASE_RELOCATION)base_relocations_dir)->VirtualAddress);

        while ( ((PIMAGE_BASE_RELOCATION)relocation_entry)->SizeOfBlock )
        {
            reloc_va = (new_base_address + ((PIMAGE_BASE_RELOCATION)relocation_entry)->VirtualAddress);
            number_of_entries = (((PIMAGE_BASE_RELOCATION)relocation_entry)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
            uiValueD = relocation_entry + sizeof(IMAGE_BASE_RELOCATION);

            while (number_of_entries--)
            {
                if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_DIR64)
                    *(ULONG_PTR*)(reloc_va + ((PIMAGE_RELOC)uiValueD)->offset) += delta;
                else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGHLOW)
                    *(DWORD*)(reloc_va + ((PIMAGE_RELOC)uiValueD)->offset) += (DWORD)delta;
                else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGH)
                    *(WORD*)(reloc_va + ((PIMAGE_RELOC)uiValueD)->offset) += HIWORD(delta);
                else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_LOW)
                    *(WORD*)(reloc_va + ((PIMAGE_RELOC)uiValueD)->offset) += LOWORD(delta);

                // get the next entry in the current relocation block
                uiValueD += sizeof(IMAGE_RELOC);
            }
            relocation_entry = relocation_entry + ((PIMAGE_BASE_RELOCATION)relocation_entry)->SizeOfBlock;
        }
    }
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // Call Dll_main
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    entry_point = (new_base_address + ((PIMAGE_NT_HEADERS)raw_dll_nt_header)->OptionalHeader.AddressOfEntryPoint);
    flushInstructionCache_func((HANDLE)-1, NULL, 0);

    ((DLLMAIN)entry_point)((HINSTANCE)new_base_address, DLL_PROCESS_ATTACH, NULL);

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    return 0;
}


EXTERN_C __declspec(dllexport) void test2()
{
    MessageBoxA(NULL, "test2!!! function", "exported function", MB_OK);
}


BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, "dll is injected Reflectively", "success!!", MB_OK);

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

