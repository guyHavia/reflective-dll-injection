#pragma once
//#include <Windows.h>
//#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <intrin.h>
#include <winnt.h>


typedef HMODULE(WINAPI* LoadLibraryA_Func)(LPCSTR);
typedef FARPROC(WINAPI* GetProcAddress_Func)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI* VirtualAlloc_Func)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* FlushInstructionCache_Func)(HANDLE, LPCVOID, SIZE_T);
typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);


#define LoadLibraryA_Value 14088
#define GetProcAddress_Value 39256
#define VirtualAlloc_Value 14808
#define FlushInstructionCache_Value 54326
#define KERNEL32 39168
#define NTDLL 16272

#define LoadLibraryA_Value1 56
#define GetProcAddress_Value1 19628
#define VirtualAlloc_Value1 14808
#define FlushInstructionCache_Value1 54326


int myStrcmp(const char* str1, const char* str2)
{
    int counter = 0;
    while (str1[counter] != '\0' && str2[counter] != '\0')
    {
        // if one string is bigger than the other
        if (str1[counter + 1] == '\0' && str2[counter + 1] != '\0' ||
            str2[counter + 1] == '\0' && str1[counter + 1] != '\0')
        {
            return 1;
        }
        else
        {
            if (str1[counter] != str2[counter])
            {
                return 1;
            }
        }
        counter++;
    }
    return 0;
}


WORD module_calc(const wchar_t* str1)
{
    int char_index = 0;
    WORD sum_of_char = 0, vector = 1;
    while (str1[char_index] != '\0')
    {
        if ((WORD)str1[char_index] < 60)
        {
            vector++;
        }
        sum_of_char += (WORD)str1[char_index];
        char_index++;
    }
    return sum_of_char * char_index * vector;
}


WORD function_calc(const char* function_name)
{
    int char_index = 0;
    WORD sum_of_char = 0, vector = 1;
    while (function_name[char_index] != '\0')
    {
        if ((WORD)function_name[char_index] < 60 || (WORD)function_name[char_index] == 80)
        {
            vector++;
        }
        sum_of_char += (WORD)function_name[char_index];
        char_index++;
    }
    return sum_of_char * char_index * vector;
}


typedef struct _UNICODE_STR
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, * PUNICODE_STR;


typedef struct _LDR_DATA_TABLE_ENTRY
{
    //LIST_ENTRY InLoadOrderLinks; // As we search from PPEB_LDR_DATA->InMemoryOrderModuleList we dont use the first entry.
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


typedef struct _PEB_LDR_DATA //, 7 elements, 0x28 bytes
{
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;


typedef struct _PEB_FREE_BLOCK // 2 elements, 0x8 bytes
{
    struct _PEB_FREE_BLOCK* pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

// struct _PEB is defined in Winternl.h but it is incomplete
typedef struct __PEB // 65 elements, 0x210 bytes
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STR usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} _PEB, * _PPEB;

typedef struct
{
    WORD	offset : 12;
    WORD	type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;
//===============================================================================================//
//===============================================================================================//
