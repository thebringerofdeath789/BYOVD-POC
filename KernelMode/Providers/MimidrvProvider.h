/**
 * @file MimidrvProvider.h
 * @author GitHub Copilot
 * @date January 29, 2026
 * @brief Mimikatz mimidrv provider implementation (KDU ID: 40/32).
 * 
 * Mimidrv provides powerful arbitrary virtual memory read/write capabilities
 * using METHOD_NEITHER IOCTLs.
 */

#pragma once

#include "BaseProvider.h"

namespace KernelMode {
    namespace Providers {

        // Mimidrv IOCTL codes
        // Note: These use METHOD_NEITHER, which is uncommon and dangerous!
        // 0x60 = VM Read, 0x61 = VM Write
        // CTL_CODE(FILE_DEVICE_UNKNOWN, 0x60, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
        #define IOCTL_MIMIDRV_VM_READ   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x60, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA) // 0x22C183
        #define IOCTL_MIMIDRV_VM_WRITE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x61, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA) // 0x22C187

        // Mimidrv doesn't use a structure for VM ops, it uses the input/output buffers purely as pointers
        // The "InputBuffer" is the target address (casted to PVOID)
        // The "OutputBuffer" is the data buffer
        // Or vice versa depending on direction.
        
        /**
         * @class MimidrvProvider
         * @brief Mimikatz driver provider
         */
        class MimidrvProvider : public BaseProvider<MemoryRequest<>> {
        public:
            MimidrvProvider();
            ~MimidrvProvider() override = default;

            bool ReadKernelMemory(uintptr_t address, void* buffer, size_t size) override;
            bool WriteKernelMemory(uintptr_t address, void* buffer, size_t size) override;

        private:
            static ProviderConfig CreateConfig();
            static ProviderLoadData CreateLoadData();
        };

    } // namespace Providers
} // namespace KernelMode
