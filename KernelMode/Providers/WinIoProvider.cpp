/**
 * @file WinIoProvider.cpp
 * @author GitHub Copilot
 * @date September 9, 2025
 * @brief MSI WinIo driver provider implementation.
 */

#include "WinIoProvider.h"

namespace KernelMode {
    namespace Providers {

        WinIoProvider::WinIoProvider() : BaseProvider(CreateConfig()) {
        }

        ProviderConfig WinIoProvider::CreateConfig() {
            ProviderConfig config = {};
            
            config.providerName = L"MSI WinIo Provider";
            config.deviceName = L"WinIo";
            config.serviceName = L"WinIo";
            config.driverId = 34; // KDU_PROVIDER_MSI_WINIO
            
            config.capabilities = 
                CAPABILITY_VIRTUAL_MEMORY |
                CAPABILITY_PHYSICAL_MEMORY |
                CAPABILITY_PREFER_PHYSICAL;
            
            // IOCTL codes
            config.readMemoryIOCTL = IOCTL_WINIO_READ_MEMORY;
            config.writeMemoryIOCTL = IOCTL_WINIO_WRITE_MEMORY;
            config.readPhysicalIOCTL = IOCTL_WINIO_READ_PHYSICAL;
            config.writePhysicalIOCTL = IOCTL_WINIO_WRITE_PHYSICAL;
            config.virtualToPhysicalIOCTL = IOCTL_WINIO_V2P_TRANSLATE;
            
            // Load data
            config.loadData = CreateLoadData();
            
            return config;
        }

        ProviderLoadData WinIoProvider::CreateLoadData() {
            ProviderLoadData loadData = {};
            
            loadData.PhysMemoryBruteForce = false;
            loadData.PML4FromLowStub = false;
            loadData.PreferPhysical = true;
            loadData.RequiresDSE = false;
            loadData.Capabilities = 
                CAPABILITY_VIRTUAL_MEMORY |
                CAPABILITY_PHYSICAL_MEMORY |
                CAPABILITY_PREFER_PHYSICAL;
            loadData.Description = L"MSI WinIo driver - Hardware I/O and memory access";
            
            return loadData;
        }

        void WinIoProvider::SetupMemoryRequest(WINIO_MEMORY_REQUEST& request, uintptr_t address, uintptr_t buffer, size_t size) {
            request.address = address;
            request.buffer = buffer;
            request.size = static_cast<ULONG>(size);
            request.reserved = 0;
        }

        uintptr_t WinIoProvider::VirtualToPhysical(uintptr_t virtualAddress) {
            if (!IsValidHandle()) {
                return 0;
            }

            WINIO_MEMORY_REQUEST request = {};
            request.address = virtualAddress;
            request.buffer = 0;
            request.size = 0;
            request.reserved = 0;

            DWORD bytesReturned = 0;
            if (DeviceIoControl(
                deviceHandle_,
                IOCTL_WINIO_V2P_TRANSLATE,
                &request,
                sizeof(request),
                &request,
                sizeof(request),
                &bytesReturned,
                NULL
            )) {
                return request.buffer; // Physical address returned in buffer field
            }

            return 0;
        }

    } // namespace Providers
} // namespace KernelMode
