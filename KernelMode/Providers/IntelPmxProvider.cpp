/**
 * @file IntelPmxProvider.cpp
 * @author GitHub Copilot
 * @date September 9, 2025
 * @brief Intel PMXDRV provider implementation.
 */

#include "IntelPmxProvider.h"

namespace KernelMode {
    namespace Providers {

        IntelPmxProvider::IntelPmxProvider() : BaseProvider(CreateConfig()) {
        }

        ProviderConfig IntelPmxProvider::CreateConfig() {
            ProviderConfig config = {};
            
            config.providerName = L"Intel PMXDRV Provider";
            config.deviceName = L"pmxdrv";
            config.serviceName = L"pmxdrv";
            config.driverId = 52; // KDU_PROVIDER_INTEL_PMXDRV
            
            config.capabilities = 
                CAPABILITY_VIRTUAL_MEMORY |
                CAPABILITY_PHYSICAL_MEMORY |
                CAPABILITY_PREFER_PHYSICAL;
            
            // IOCTL codes
            config.readMemoryIOCTL = IOCTL_PMXDRV_READ_MEMORY;
            config.writeMemoryIOCTL = IOCTL_PMXDRV_WRITE_MEMORY;
            config.readPhysicalIOCTL = IOCTL_PMXDRV_READ_PHYSICAL;
            config.writePhysicalIOCTL = IOCTL_PMXDRV_WRITE_PHYSICAL;
            config.virtualToPhysicalIOCTL = IOCTL_PMXDRV_V2P_TRANSLATE;
            
            // Load data
            config.loadData = CreateLoadData();
            
            return config;
        }

        ProviderLoadData IntelPmxProvider::CreateLoadData() {
            ProviderLoadData loadData = {};
            
            loadData.PhysMemoryBruteForce = false;
            loadData.PML4FromLowStub = false;
            loadData.PreferPhysical = true;
            loadData.RequiresDSE = false;
            loadData.Capabilities = 
                CAPABILITY_VIRTUAL_MEMORY |
                CAPABILITY_PHYSICAL_MEMORY |
                CAPABILITY_PREFER_PHYSICAL;
            loadData.Description = L"Intel PMXDRV - Modern Intel driver with memory access";
            
            return loadData;
        }

        void IntelPmxProvider::SetupMemoryRequest(PMXDRV_MEMORY_REQUEST& request, uintptr_t address, uintptr_t buffer, size_t size) {
            request.address = static_cast<ULONG64>(address);
            request.buffer = static_cast<ULONG64>(buffer);
            request.size = static_cast<ULONG>(size);
            request.operation = 0; // Default operation
        }

        uintptr_t IntelPmxProvider::VirtualToPhysical(uintptr_t virtualAddress) {
            if (!IsValidHandle()) {
                return 0;
            }

            PMXDRV_MEMORY_REQUEST request = {};
            request.address = static_cast<ULONG64>(virtualAddress);
            request.buffer = 0;
            request.size = 0;
            request.operation = 1; // V2P operation

            DWORD bytesReturned = 0;
            if (DeviceIoControl(
                deviceHandle_,
                IOCTL_PMXDRV_V2P_TRANSLATE,
                &request,
                sizeof(request),
                &request,
                sizeof(request),
                &bytesReturned,
                NULL
            )) {
                return static_cast<uintptr_t>(request.buffer);
            }

            return 0;
        }

    } // namespace Providers
} // namespace KernelMode
