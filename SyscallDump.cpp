#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>

// Function to get architecture type
bool Is64BitOS() {
    BOOL isWow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &isWow64);
    return isWow64 || (sizeof(void*) == 8);
}

void DumpSyscallNumbers(const char* dllPath) {
    // Open ntdll.dll from disk
    HANDLE file = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open " << dllPath << std::endl;
        return;
    }
    std::cout << "Successfully opened " << dllPath << std::endl;

    // Map the file into memory
    HANDLE mapping = CreateFileMappingA(file, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (mapping == NULL) {
        std::cerr << "Failed to create file mapping" << std::endl;
        CloseHandle(file);
        return;
    }
    std::cout << "Successfully created file mapping" << std::endl;

    // Get the base address of the mapped file
    PVOID baseAddress = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    if (baseAddress == NULL) {
        std::cerr << "Failed to map view of file" << std::endl;
        CloseHandle(mapping);
        CloseHandle(file);
        return;
    }
    std::cout << "Successfully mapped view of file" << std::endl;

    // Parse DOS header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Invalid DOS signature" << std::endl;
        UnmapViewOfFile(baseAddress);
        CloseHandle(mapping);
        CloseHandle(file);
        return;
    }
    std::cout << "DOS header is valid" << std::endl;

    // Parse PE header
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)baseAddress + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "Invalid NT signature" << std::endl;
        UnmapViewOfFile(baseAddress);
        CloseHandle(mapping);
        CloseHandle(file);
        return;
    }
    std::cout << "NT header is valid" << std::endl;

    // Locate the export directory
    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRVA == 0) {
        std::cerr << "No export directory found" << std::endl;
        UnmapViewOfFile(baseAddress);
        CloseHandle(mapping);
        CloseHandle(file);
        return;
    }
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)baseAddress + exportDirRVA);
    std::cout << "Located export directory" << std::endl;

    DWORD* nameRvas = (DWORD*)((BYTE*)baseAddress + exportDirectory->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)baseAddress + exportDirectory->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)((BYTE*)baseAddress + exportDirectory->AddressOfFunctions);

    std::cout << "Syscall Numbers in " << dllPath << ":\n";

    // Determine if the OS is 64-bit
    bool is64Bit = Is64BitOS();

    // Iterate through exported functions
    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
        const char* functionName = (const char*)((BYTE*)baseAddress + nameRvas[i]);

        // Check if the function name starts with "Nt" or "Zw"
        if (strncmp(functionName, "Nt", 2) == 0 || strncmp(functionName, "Zw", 2) == 0) {
            std::cout << "Checking function: " << functionName << std::endl;

            WORD ordinal = ordinals[i];
            DWORD functionRva = functions[ordinal];
            BYTE* functionAddress = (BYTE*)baseAddress + functionRva;
            std::cout << "Function " << functionName << " found at address: " << std::hex << (uintptr_t)functionAddress << std::dec << std::endl;

            // Scan the first few bytes of the function to find the syscall number
            for (int j = 0; j < 20; j++) {
                if (is64Bit) {
                    // For 64-bit, look for "mov r10, rcx" and "mov eax, imm32"
                    if (functionAddress[j] == 0x4C && functionAddress[j + 1] == 0x8B && functionAddress[j + 2] == 0xD1) {
                        if (functionAddress[j + 3] == 0xB8) {
                            DWORD syscallNumber = *(DWORD*)(functionAddress + j + 4);
                            std::cout << functionName << " : " << syscallNumber << std::endl;
                            break;
                        }
                    }
                }
                else {
                    // For 32-bit, look for "mov eax, imm32"
                    if (functionAddress[j] == 0xB8) {
                        DWORD syscallNumber = *(DWORD*)(functionAddress + j + 1);
                        std::cout << functionName << " : " << syscallNumber << std::endl;
                        break;
                    }
                }
            }
        }
    }

    // Cleanup
    UnmapViewOfFile(baseAddress);
    CloseHandle(mapping);
    CloseHandle(file);
}

int main() {
    DumpSyscallNumbers("C:\\Windows\\System32\\ntdll.dll");
    return 0;
}
