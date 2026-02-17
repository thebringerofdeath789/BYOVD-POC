/**
 * @file WinIoProvider.h
 * @author GitHub Copilot  
 * @date September 9, 2025
 * @brief MSI WinIo driver provider implementation (KDU ID: 34).
 * 
 * WinIo provides hardware I/O access and full memory operations.
 * Excellent Win 10/11 compatibility with low detection rates.
 */

#pragma once

#include "BaseProvider.h"

namespace KernelMode {
    namespace Providers {

        // WinIo-specific IOCTL codes (from KDU winio.h)
        #define IOCTL_WINIO_READ_MEMORY         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
        #define IOCTL_WINIO_WRITE_MEMORY        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
        #define IOCTL_WINIO_READ_PHYSICAL       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
        #define IOCTL_WINIO_WRITE_PHYSICAL      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
        #define IOCTL_WINIO_V2P_TRANSLATE       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)

        // WinIo memory request structure (matches KDU implementation)
        #pragma pack(push, 1)
        struct WINIO_MEMORY_REQUEST {
            using TAddress = uintptr_t;
            using TSize = ULONG;
            uintptr_t address;
            uintptr_t buffer;
            ULONG size;
            ULONG reserved;
        };
        #pragma pack(pop)

        /**
         * @class WinIoProvider
         * @brief MSI WinIo vulnerable driver provider
         */
        class WinIoProvider : public BaseProvider<WINIO_MEMORY_REQUEST> {
        public:
            WinIoProvider();
            ~WinIoProvider() override = default;

            // Override for WinIo-specific V2P implementation
            uintptr_t VirtualToPhysical(uintptr_t virtualAddress) override;

        protected:
            void SetupMemoryRequest(WINIO_MEMORY_REQUEST& request, uintptr_t address, uintptr_t buffer, size_t size) override;

        private:
            static ProviderConfig CreateConfig();
            static ProviderLoadData CreateLoadData();
        };

    } // namespace Providers
} // namespace KernelMode
