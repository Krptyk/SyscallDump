
# Syscall Dumper

This project provides a utility to extract syscall numbers from `ntdll.dll` on Windows systems. It parses the PE headers and export directory of `ntdll.dll` to identify and extract syscall numbers for functions starting with "Nt".

## Features

- Opens and maps `ntdll.dll` into memory
- Parses the DOS and PE headers
- Locates the export directory
- Identifies functions starting with "Nt"
- Extracts and prints syscall numbers for the identified functions

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
    ./SyscallDump.exe
    ```

## Example Output

```
Successfully opened C:\Windows\System32\ntdll.dll
Successfully created file mapping
Successfully mapped view of file
DOS header is valid
NT header is valid
Located export directory
Syscall Numbers in C:\Windows\System32\ntdll.dll:
Checking function: NtAcceptConnectPort
Function NtAcceptConnectPort found at address: 2d2489bd010
NtAcceptConnectPort : 2
Checking function: NtAccessCheck
Function NtAccessCheck found at address: 2d2489bcfd0
NtAccessCheck : 0
Checking function: NtAccessCheckAndAuditAlarm
Function NtAccessCheckAndAuditAlarm found at address: 2d2489bd4f0
NtAccessCheckAndAuditAlarm : 41
Checking function: NtAccessCheckByType
Function NtAccessCheckByType found at address: 2d2489bdc20
NtAccessCheckByType : 99
...
```

## Code Explanation

- `Is64BitOS()` function checks if the operating system is 64-bit.
- `DumpSyscallNumbers()` function:
  - Opens `ntdll.dll` from disk.
  - Maps the file into memory.
  - Parses the DOS and PE headers.
  - Locates the export directory.
  - Iterates through exported functions and checks for functions starting with "Nt".
  - Extracts and prints syscall numbers.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

- [Krptyk](https://github.com/Krptyk)


