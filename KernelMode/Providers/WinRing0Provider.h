#pragma once
#include "IProvider.h"
#include <windows.h>

namespace KernelMode {
    namespace Providers {

        class WinRing0Provider : public IProvider {
        public:
            static ProviderLoadData loadData;

            WinRing0Provider();
            virtual ~WinRing0Provider();

            // IProvider methods
            bool Initialize(ULONG driverId = 0, bool bypassDSE = false) override;
            void Deinitialize() override;
            std::wstring GetProviderName() const override;
            
            bool ReadKernelMemory(uintptr_t address, void* buffer, size_t size) override;
            bool WriteKernelMemory(uintptr_t address, void* buffer, size_t size) override;
            bool ReadPhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) override;
            bool WritePhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) override;
            bool ReadMsr(ULONG msrIndex, ULONG64* value) override;
            bool WriteMsr(ULONG msrIndex, ULONG64 value) override;
            
            bool BypassDSE() override;
            ULONG GetCapabilities() const override;
            const ProviderLoadData* GetLoadData() const override;
            
            uintptr_t VirtualToPhysical(uintptr_t virtualAddress) override;

            // Missing overrides
            uintptr_t AllocateKernelMemory(size_t size, uintptr_t* physicalAddress = nullptr) override { return 0; }
            bool FreeKernelMemory(uintptr_t virtualAddress, size_t size) override { return false; }
            bool CreateSystemThread(uintptr_t startAddress, uintptr_t parameter = 0) override { return false; }

        private:
            HANDLE deviceHandle;
            SC_HANDLE serviceHandle;
            std::wstring dirDriverPath;
            
            bool OpenDeviceHandle();
            bool InstallDriverService();
        };

    }
}
