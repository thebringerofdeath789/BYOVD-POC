/**
 * @file AsrDrvProvider.h
 * @author GitHub Copilot
 * @date January 29, 2026
 * @brief ASRock AsrDrv provider implementation (KDU ID: 62).
 * 
 * AsrDrv provides MSR access and physical memory mapping capabilities.
 * Commonly used for MSR-based exploits and physical memory attacks.
 */

#pragma once

#include "BaseProvider.h"

namespace KernelMode {
    namespace Providers {

        // AsrDrv IOCTL codes (Common to AsrDrv101/102/103/104)
        // These drivers typically use METHOD_BUFFERED
        
        // MSR Operations
        #define IOCTL_ASR_READ_MSR          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS) // 0x222840
        #define IOCTL_ASR_WRITE_MSR         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS) // 0x222844

        // Port I/O
        #define IOCTL_ASR_READ_PORT_BYTE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS) // 0x222810
        #define IOCTL_ASR_WRITE_PORT_BYTE   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS) // 0x222814
        
        // Physical Memory
        // Note: AsrDrv functionality for PhysMem varies by version. 
        // We will focus on physical memory access via standard map or custom logic if available.
        // Some versions support direct physical read/write via 0x222808/0x22280C (Like WinRing0/OLS)
        // because they often embed OLS libraries.
        #define IOCTL_ASR_READ_MEMORY       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS) // 0x222808
        #define IOCTL_ASR_WRITE_MEMORY      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS) // 0x22280C

        // AsrDrv memory request structure (Matches WinRing0/OLS)
        #pragma pack(push, 1)
        struct ASR_MEMORY_REQUEST {
            using TAddress = LARGE_INTEGER;
            using TSize = ULONG;
            LARGE_INTEGER Address; // Physical Address
            ULONG Size;
            ULONG Data;            // For 1/2/4 byte access, or ignored for buffer?
                                   // Note: AsrDrv typically does 1/2/4 byte generic I/O.
                                   // For bulk copy, it might be different.
        };
        
        struct ASR_MSR_REQUEST {
            ULONG Register;
            ULARGE_INTEGER Value;
        };
        #pragma pack(pop)

        // Dummy struct for BaseProvider template
        struct AsrDummyRequest {
            using TAddress = uintptr_t;
            using TSize = size_t;
            uintptr_t address;
            uintptr_t buffer;
            size_t size;
        };

        /**
         * @class AsrDrvProvider
         * @brief ASRock vulnerable driver provider
         */
        class AsrDrvProvider : public BaseProvider<AsrDummyRequest> {
        public:
            AsrDrvProvider();
            ~AsrDrvProvider() override = default;

            // Override to handle AsrDrv specific chunking
            bool ReadPhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) override;
            bool WritePhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) override;

            // MSR Operations
            bool ReadMsr(ULONG msrIndex, ULONG64* value) override;
            bool WriteMsr(ULONG msrIndex, ULONG64 value) override;

        private:
            static ProviderConfig CreateConfig();
            static ProviderLoadData CreateLoadData();
        };

    } // namespace Providers
} // namespace KernelMode
