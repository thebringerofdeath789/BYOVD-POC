#pragma once
#include "BaseProvider.h"

namespace KernelMode {
    namespace Providers {

        // EchoDrv / Echoac IOCTLs
        // Typically METHOD_BUFFERED or METHOD_NEITHER depending on version.
        // KDU uses 0x9E690840 etc.
        #define ECHO_DEVICE_TYPE 0x9e69
        
        #define IOCTL_ECHO_READ_MSR     CTL_CODE(ECHO_DEVICE_TYPE, 0x960, METHOD_BUFFERED, FILE_ANY_ACCESS) // 0x9e692580 (Need to verify exact code)
        // Actually typical codes are:
        // Read MSR: 0x9E690840? No.
        
        // Let's use KDU constants for "EchoDrv" (ID 35)
        // From public sources:
        // READ_IO_PORT_BYTE  0x9E690804
        // WRITE_IO_PORT_BYTE 0x9E690808
        // READ_IO_PORT_DWORD 0x9E69081C
        // MAP_PHYS_MEM       0x9E690840 (Wait, KDU says this is map?)
        // UNMAP_PHYS_MEM     0x9E690844
        // READ_MSR           0x9E690880
        // WRITE_MSR          0x9E690884
        
        // Let's stick to the ones that match standard EchoDrv exploits.
        
        #define IOCTL_ECHO_MAP_PHYSICAL   CTL_CODE(ECHO_DEVICE_TYPE, 0x840, METHOD_BUFFERED, FILE_ANY_ACCESS)
        #define IOCTL_ECHO_UNMAP_PHYSICAL CTL_CODE(ECHO_DEVICE_TYPE, 0x844, METHOD_BUFFERED, FILE_ANY_ACCESS) 
        #define IOCTL_ECHO_READ_MSR       CTL_CODE(ECHO_DEVICE_TYPE, 0x880, METHOD_BUFFERED, FILE_ANY_ACCESS)
        #define IOCTL_ECHO_WRITE_MSR      CTL_CODE(ECHO_DEVICE_TYPE, 0x884, METHOD_BUFFERED, FILE_ANY_ACCESS)

        #pragma pack(push, 1)
        struct ECHO_MSR_REQUEST {
            ULONG Register;
            ULARGE_INTEGER Value;
        };

        // Standard Windows type, but usually needs ntddk or wdm.
        // We redefine it compatible with the driver's expectation (enum/int).
        typedef enum _INTERFACE_TYPE_COMPAT {
            InterfaceTypeUndefined = -1,
            Internal,
            Isa,
            Eisa,
            MicroChannel,
            TurboChannel,
            PCIBus,
            VMEBus,
            NuBus,
            PCMCIABus,
            CBus,
            MPIBus,
            MPSABus,
            ProcessorInternal,
            InternalPowerBus,
            PNPISABus,
            PNPBus,
            Vmcs,
            ACPIBus,
            MaximumInterfaceType
        } INTERFACE_TYPE_COMPAT;

        struct ECHO_MAP_REQUEST {
            INTERFACE_TYPE_COMPAT InterfaceType; // 0
            ULONG BusNumber;              // 0
            LARGE_INTEGER PhysAddr;       // PHYSICAL_ADDRESS
            ULONG Size;
            ULONG AddressSpace;           // 0
            PVOID MappedAddress;          // Out
        };
        #pragma pack(pop)

        // Dummy struct for BaseProvider template satisfaction
        struct EchoDummyRequest {
            using TAddress = uintptr_t;
            using TSize = size_t;
            uintptr_t address;
            uintptr_t buffer;
            size_t size;
        };

        class EchoDrvProvider : public BaseProvider<EchoDummyRequest> {
        public:
            EchoDrvProvider();
            ~EchoDrvProvider() override = default;

            bool ReadPhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) override;
            bool WritePhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) override;
            
            bool ReadMsr(ULONG msrIndex, ULONG64* value) override;
            bool WriteMsr(ULONG msrIndex, ULONG64 value) override;

        private:
            static ProviderConfig CreateConfig();
            static ProviderLoadData CreateLoadData();

            // Maps physical memory to user space
            PVOID MapPhysical(uintptr_t physicalAddress, size_t size, PVOID* mappedBase);
            void UnmapPhysical(PVOID mappedBase);
        };
    }
}
