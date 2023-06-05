#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <iostream>
#include <winnt.h>

typedef DWORD(WINAPI* self_load)();


int main(int argc, char* argv[]) {
    DWORD currentProcessID;
    HMODULE reflectiveDll;
    self_load self_loaderAddress;
    DWORD returnValue;

    ////reflectiveDll = LoadLibraryA("C:\\Users\\guy\\Desktop\\projects\\reflectiveDLL\\x64\\Debug\\reflectiveDLL.dll");
    //reflectiveDll = LoadLibraryA("C:\\Users\\guy\\Desktop\\projects\\reflectiveDll\\x64\\Debug\\reflectiveDLL.dll");
    //self_loaderAddress = (self_load)GetProcAddress(reflectiveDll, "self_loader");
    //returnValue = self_loaderAddress();
    //printf("%d", returnValue);
    //
    
    while (true)
    {
        currentProcessID = GetCurrentProcessId();
        printf("\nthe current process id is: %d\n", currentProcessID);
        Sleep(5000);
    }
    return 0;
}