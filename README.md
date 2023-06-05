# reflective-dll-injection
This is my implementation of https://github.com/stephenfewer/ReflectiveDLLInjection project. it is heavely leaned on his project but with much more order and explanation.
**The Implementation works on both x64 & x32 bit operation systems.**

## this repository contains main files:
1. Reflective_Loader.exe - which perform the loading of our dll into the memory of another process.
2. reflective_Dll.dll - our dll which get loaded to another process memory.
3. victim.exe - a process which runs endlessely, we will inject our dll into this process memory.

### RVA vs Offset
* RVA (relative virtual address) is an address which is relative to process's base address, for example if a variable has a RVA of 0x10 and the process base address is 0x100 so the VA (virtual address) of that variable is: base address + RVA = 0x100 + 0x10 = 0x110.
the base address of a process is saved in "optional header -> ImageBase" value.
* Offset is the number of bytes from the beginning of the file (on disk) untill a certain point. 
* for more details: https://tech-zealots.com/malware-analysis/understanding-concepts-of-va-rva-and-offset
* Because we are reading the file as raw data, the parsing of the pe headers won't work because the dll isn't loaded to memory so "Imagebase" will lead to ambiguous locations.
Solving this issue accomplished by writing "Rva2Offset" function which parses the sections header in order to find which section a rva is located and returns the offset from that rva.


### Linker and strings:
One of the linker responsibilities is to resolve the references the compiler make to strings location in memory, the linker make sure each reference to a string will lead to a valid memory address that contains the string.
Because our dll doesn't got loaded regularly (our reflective_loader is the loader) we cannot use strings, there will be no loader whom resolve those addresses, we represents those functions names with our "hash" algorithem thus represent those strings as WORD.


## Reflective_loader:
the code inject our dll to a victim process with the following steps:
1. Gets a handle to the dll file.
2. Reads the dll content into a buffer & get the file size.
3. Gets a handle to the victim process (need "sedebugprivilege" privilege so run the process as Admin).
4. Parse the dll data to find the location of the "self_loader" function.
5. Allocate memory in victim.exe and write the dll data that we read earlier (step 2).
6. Create remote thread for victim.exe with an entry point of "self_loader" function.


## reflective_Dll:
Because our remote thread's entry point is the location of "self-loader" function, this function will start first.
1. Finding dll's base address, accomplished with "#pragma intrinsic( _ReturnAddress )" instruction which returns our current location, then we go back byte after byte untill we find 'MZ' byte that represent the dll's magic number (additional checks are performed).
2. Parse the PEB structure & get the dll's modules (kernel32.dll , ntdll.dll).
3. Parse those modules & extract the addresses of the functions: virtualAlloc, Loadlibrary, GetprocAddr from kernel32.dll & FlushInstructionCache from ntdll.dll.
4. Use VirtualAlloc function that we extracted to allocate new memory location which we will load the dll as a dll and not as raw data.
5. Relocate the dll headers & sections to the new location.
6. Loading all the necessary dependencies our dll might have (parse its import table and load all the necessary functions).
7. Perform all the relocations a regular loader will perform.
8. Find the entry point of "MainDll" function and call it.
