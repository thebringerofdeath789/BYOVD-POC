/**
 * @file Syscall.cpp
 * @author Gregory King
 * @date August 14, 2025
 * @brief This file contains the implementation of the Syscall class.
 *
 * Implements the logic to parse the ntdll.dll export table at runtime
 * to build a map of function names to their corresponding syscall indices.
 */

#include "Syscall.h"
#include <winternl.h>

namespace KernelMode {

    Syscall& Syscall::GetInstance() {
        static Syscall instance;
        return instance;
    }

    Syscall::Syscall() {
        // BUG-015 FIX: Load fresh ntdll from disk to avoid user-mode hooks
        // Hooks placed by AV/EDR in the in-memory ntdll often modify the syscall stubs.
        // Reading from disk ensures we get the clean "golden" syscall numbers.
        
        char sysPath[MAX_PATH];
        GetSystemDirectoryA(sysPath, MAX_PATH);
        std::string ntdllPath = std::string(sysPath) + "\\ntdll.dll";
        
        HMODULE ntdll = LoadLibraryExA(ntdllPath.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (!ntdll) {
             // Fallback to loaded module if disk read fails (unlikely)
             ntdll = GetModuleHandleA("ntdll.dll");
        }
        if (!ntdll) return;

        auto dosHeader = (PIMAGE_DOS_HEADER)ntdll;
        auto ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)ntdll + dosHeader->e_lfanew);
        auto exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)ntdll + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        auto names = (PDWORD)((BYTE*)ntdll + exportDir->AddressOfNames);
        auto functions = (PDWORD)((BYTE*)ntdll + exportDir->AddressOfFunctions);
        auto ordinals = (PWORD)((BYTE*)ntdll + exportDir->AddressOfNameOrdinals);

        for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
            std::string funcName = (char*)ntdll + names[i];
            if (funcName.rfind("Nt", 0) == 0) { // Check if it starts with "Nt"
                // The syscall index is found in the first few bytes of the function stub.
                // mov r10, rcx
                // mov eax, <syscall_index>
                // syscall
                // ret
                BYTE* funcAddr = (BYTE*)ntdll + functions[ordinals[i]];
                if (*(funcAddr) == 0x4C && *(funcAddr + 3) == 0xB8) {
                    DWORD syscallIndex = *(DWORD*)(funcAddr + 4);
                    syscallMap[funcName] = syscallIndex;
                }
            }
        }
    }

    DWORD Syscall::GetSyscallIndex(const std::string& functionName) {
        auto it = syscallMap.find(functionName);
        if (it != syscallMap.end()) {
            return it->second;
        }
        return (DWORD)-1;
    }
}