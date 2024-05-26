
# Syscall and Function Address Dumper

This project provides a utility to extract syscall numbers from `ntdll.dll` and function addresses from `kernel32.dll` on Windows systems. It parses the PE headers and export directory to identify and extract syscall numbers for functions starting with "Nt" in `ntdll.dll` and retrieves function addresses for all exported functions in `kernel32.dll`.

## Features

- Opens and maps `ntdll.dll` or `kernel32.dll` into memory
- Parses the DOS and PE headers
- Locates the export directory
- Identifies functions starting with "Nt" or "Zw" in `ntdll.dll`
- Extracts and prints syscall numbers for the identified functions in `ntdll.dll`
- Retrieves and prints function addresses for all exported functions in `kernel32.dll`

## Requirements

- Windows OS
- Visual Studio or any C++ compiler supporting Windows API

## Usage

1. Clone the repository:
    ```sh
    git clone https://github.com/Krptyk/SyscallDump.git
    cd SyscallDump
    ```

2. Build the project using Visual Studio or any compatible C++ compiler.

3. Run the executable:
    ```sh
    ./SyscallDump.exe <ntdll|kernel32>
    ```

## Example Output

### Kernel32 Example
```
.\SyscallDump.exe kernel32
Successfully loaded C:\Windows\System32\kernel32.dll
Base address of C:\Windows\System32\kernel32.dll: 0x7ff96d9f0000
DOS header is valid
NT header is valid
Located export directory
Exported Functions in C:\Windows\System32\kernel32.dll:
AcquireSRWLockExclusive found at address: 0x7ff96db190a0
AcquireSRWLockShared found at address: 0x7ff96db11760
ActivateActCtx found at address: 0x7ff96da10390
ActivateActCtxWorker found at address: 0x7ff96da0ba10
AddAtomA found at address: 0x7ff96da49230

```

### Ntdll Example
```
.\SyscallDump.exe ntdll
Successfully loaded C:\Windows\System32\ntdll.dll
Base address of C:\Windows\System32\ntdll.dll: 0x7ff96daf0000
DOS header is valid
NT header is valid
Located export directory
Exported Functions in C:\Windows\System32\ntdll.dll:
NtAcceptConnectPort found at address: 0x7ff96db8d010
Syscall number for NtAcceptConnectPort : 2
NtAccessCheck found at address: 0x7ff96db8cfd0
Syscall number for NtAccessCheck : 0
NtAccessCheckAndAuditAlarm found at address: 0x7ff96db8d4f0
Syscall number for NtAccessCheckAndAuditAlarm : 41
NtAccessCheckByType found at address: 0x7ff96db8dc20
Syscall number for NtAccessCheckByType : 99
NtAccessCheckByTypeAndAuditAlarm found at address: 0x7ff96db8daf0
Syscall number for NtAccessCheckByTypeAndAuditAlarm : 89
NtAccessCheckByTypeResultList found at address: 0x7ff96db8dc40
Syscall number for NtAccessCheckByTypeResultList : 100

```

## Code Explanation

- `Is64BitOS()` function checks if the operating system is 64-bit.
- `DumpFunctionAddressesAndSyscallNumbers()` function:
  - Loads the specified DLL into the process address space.
  - Retrieves and prints the base address of the DLL.
  - Parses the DOS and PE headers.
  - Locates the export directory.
  - Iterates through exported functions.
  - Retrieves and prints function addresses for all exported functions in `kernel32.dll`.
  - Identifies functions starting with "Nt" or "Zw" in `ntdll.dll`.
  - Extracts and prints syscall numbers for the identified functions in `ntdll.dll`.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

- [Krptyk](https://github.com/Krptyk)
