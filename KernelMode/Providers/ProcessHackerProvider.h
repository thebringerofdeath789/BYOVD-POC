#pragma once
#include "IProvider.h"
#include <windows.h>

namespace KernelMode {
    namespace Providers {

        #ifndef PCLIENT_ID
        typedef struct _CLIENT_ID {
            HANDLE UniqueProcess;
            HANDLE UniqueThread;
        } CLIENT_ID, *PCLIENT_ID;
        #endif

        // KPH Structures
        typedef struct _KPH_OPEN_PROCESS_REQUEST {
            PHANDLE ProcessHandle;
            ACCESS_MASK DesiredAccess;
            PCLIENT_ID ClientId;
        } KPH_OPEN_PROCESS_REQUEST, *PKPH_OPEN_PROCESS_REQUEST;

        typedef struct _KPH_DUPLICATE_OBJECT_REQUEST {
            HANDLE SourceProcessHandle;
            HANDLE SourceHandle;
            HANDLE TargetProcessHandle;
            PHANDLE TargetHandle;
            ACCESS_MASK DesiredAccess;
            ULONG HandleAttributes;
            ULONG Options;
        } KPH_DUPLICATE_OBJECT_REQUEST, *PKPH_DUPLICATE_OBJECT_REQUEST;

        class ProcessHackerProvider : public IProvider {
        public:
            static ProviderLoadData loadData;

            ProcessHackerProvider();
            virtual ~ProcessHackerProvider();

            // IProvider methods
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

        private:
            HANDLE deviceHandle;
            SC_HANDLE serviceHandle;
            std::wstring dirDriverPath;
            HANDLE physicalMemorySection;
            
            bool OpenDeviceHandle();
            bool InstallDriverService();

            // KPH Specific Primitives
            bool KphOpenProcess(HANDLE processId, ACCESS_MASK desiredAccess, PHANDLE processHandle);
            bool KphDuplicateHandle(HANDLE sourceProcessHandle, HANDLE sourceHandle, PHANDLE targetHandle);
            bool AcquirePhysicalMemoryHandle();
        };

    }
}
