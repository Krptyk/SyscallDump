#include <Windows.h>
#include <iostream>
#include <string>

// Function to get architecture type
bool Is64BitOS() {
    BOOL isWow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &isWow64);
    return isWow64 || (sizeof(void*) == 8);
}

void DumpFunctionAddressesAndSyscallNumbers(const char* dllPath, bool dumpAllFunctions) {
    // Load the specified DLL into the process address space
    HMODULE hModule = LoadLibraryA(dllPath);
    if (hModule == NULL) {
        std::cerr << "Failed to load " << dllPath << std::endl;
        return;
    }
    std::cout << "Successfully loaded " << dllPath << std::endl;

    // Get the base address of the loaded module
    PVOID baseAddress = (PVOID)hModule;
    std::cout << "Base address of " << dllPath << ": 0x" << std::hex << (uintptr_t)baseAddress << std::dec << std::endl;

    // Parse DOS header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Invalid DOS signature" << std::endl;
        FreeLibrary(hModule);
        return;
    }
    std::cout << "DOS header is valid" << std::endl;

    // Parse PE header
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)baseAddress + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "Invalid NT signature" << std::endl;
        FreeLibrary(hModule);
        return;
    }
    std::cout << "NT header is valid" << std::endl;

    // Locate the export directory
    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRVA == 0) {
        std::cerr << "No export directory found" << std::endl;
        FreeLibrary(hModule);
        return;
    }
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)baseAddress + exportDirRVA);
    std::cout << "Located export directory" << std::endl;

    DWORD* nameRvas = (DWORD*)((BYTE*)baseAddress + exportDirectory->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)baseAddress + exportDirectory->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)((BYTE*)baseAddress + exportDirectory->AddressOfFunctions);

    std::cout << "Exported Functions in " << dllPath << ":\n";

    // Determine if the OS is 64-bit
    bool is64Bit = Is64BitOS();

    // Iterate through exported functions
    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
        const char* functionName = (const char*)((BYTE*)baseAddress + nameRvas[i]);

        // Check if the function name starts with "Nt" or "Zw" for ntdll, or dump all for kernel32, user32, or ws2_32
        if (dumpAllFunctions || strncmp(functionName, "Nt", 2) == 0 || strncmp(functionName, "Zw", 2) == 0) {
            // Get the address of the function using GetProcAddress
            FARPROC functionAddress = GetProcAddress(hModule, functionName);
            if (functionAddress == NULL) {
                std::cerr << "Failed to find function: " << functionName << std::endl;
            }
            else {
                std::cout << functionName << " found at address: 0x" << std::hex << (uintptr_t)functionAddress << std::dec << std::endl;

                // Scan the first few bytes of the function to find the syscall number
                BYTE* functionCode = (BYTE*)functionAddress;
                for (int j = 0; j < 20; j++) {
                    if (is64Bit) {
                        // For 64-bit, look for "mov r10, rcx" and "mov eax, imm32"
                        if (functionCode[j] == 0x4C && functionCode[j + 1] == 0x8B && functionCode[j + 2] == 0xD1) {
                            if (functionCode[j + 3] == 0xB8) {
                                DWORD syscallNumber = *(DWORD*)(functionCode + j + 4);
                                std::cout << "Syscall number for " << functionName << " : " << syscallNumber << std::endl;
                                break;
                            }
                        }
                    }
                    else {
                        // For 32-bit, look for "mov eax, imm32"
                        if (functionCode[j] == 0xB8) {
                            DWORD syscallNumber = *(DWORD*)(functionCode + j + 1);
                            std::cout << "Syscall number for " << functionName << " : " << syscallNumber << std::endl;
                            break;
                        }
                    }
                }
            }
        }
    }

    // Free the loaded module
    FreeLibrary(hModule);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <ntdll|kernel32|user32|ws2_32>" << std::endl;
        return 1;
    }

    std::string dllFlag = argv[1];
    std::string dllPath;
    bool dumpAllFunctions = false;

    if (dllFlag == "ntdll") {
        dllPath = "C:\\Windows\\System32\\ntdll.dll";
    }
    else if (dllFlag == "kernel32") {
        dllPath = "C:\\Windows\\System32\\kernel32.dll";
        dumpAllFunctions = true;
    }
    else if (dllFlag == "user32") {
        dllPath = "C:\\Windows\\System32\\user32.dll";
        dumpAllFunctions = true;
    }
    else if (dllFlag == "ws2_32") {
        dllPath = "C:\\Windows\\System32\\ws2_32.dll";
        dumpAllFunctions = true;
    }
    else {
        std::cerr << "Invalid argument: " << dllFlag << std::endl;
        std::cerr << "Usage: " << argv[0] << " <ntdll|kernel32|user32|ws2_32>" << std::endl;
        return 1;
    }

    DumpFunctionAddressesAndSyscallNumbers(dllPath.c_str(), dumpAllFunctions);

    return 0;
}
