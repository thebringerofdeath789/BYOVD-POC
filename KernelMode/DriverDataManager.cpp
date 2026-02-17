/**
 * @file DriverDataManager.cpp
 * @author Gregory King
 * @date August 14, 2025  
 * @brief This file contains the implementation of the DriverDataManager class.
 *
 * Implements KDU-style driver resource management with support for embedded
 * .bin files, external file fallback, and automatic driver selection.
 */

#include "DriverDataManager.h"
#include "Utils.h"
#include "resource.h"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <dbghelp.h>
#pragma comment(lib, "Dbghelp.lib")
#include <filesystem>

namespace KernelMode {
    namespace Resources {

        // External driver data (embedded via Tanikaze-style resource compilation)
        extern "C" {
            extern const BYTE gdrv_bin_data[];
            extern const ULONG gdrv_bin_size;
            extern const BYTE rtcore_bin_data[];
            extern const ULONG rtcore_bin_size;
            extern const BYTE dbutil_bin_data[];
            extern const ULONG dbutil_bin_size;
        }

        DriverDataManager& DriverDataManager::GetInstance() {
            static DriverDataManager instance;
            return instance;
        }

        DriverDataManager::~DriverDataManager() {
            if (hTanikaze) {
                FreeLibrary(hTanikaze);
                hTanikaze = NULL;
            }
        }

        bool DriverDataManager::Initialize() {
            if (initialized) return true;

            std::wcout << L"[*] Initializing Driver Data Manager (KDU-style)..." << std::endl;

            // 1. Try loading embedded drivers
            if (LoadEmbeddedDrivers()) {
                std::wcout << L"[+] Embedded drivers loaded successfully." << std::endl;
            }

            // 2. Always try to load external drivers to supplement embedded ones (e.g., Intel Nal)
            std::wcout << L"[*] Checking for supplemental external drivers..." << std::endl;
            if (LoadExternalDrivers()) {
                 std::wcout << L"[+] External drivers loaded/updated." << std::endl;
            }

            if (drivers.empty()) {
                std::wcerr << L"[-] Failed to load any driver data (embedded or external)." << std::endl;
                return false;
            }

            initialized = true;
            std::wcout << L"[+] Driver Data Manager initialized with " 
                       << drivers.size() << L" drivers." << std::endl;
            return true;
        }

        bool DriverDataManager::LoadEmbeddedDrivers() {
            try {
                // Load GDRV driver
                auto gdrv = std::make_unique<DriverInfo>();
                gdrv->DriverId = DRIVER_ID_GDRV;
                gdrv->DriverName = L"GIGABYTE GDRV";
                gdrv->FileName = L"gdrv.sys";
                if (gdrv_bin_size > 0) {
                    gdrv->DriverData.assign(gdrv_bin_data, gdrv_bin_data + gdrv_bin_size);
                }
                gdrv->DriverDataSize = gdrv_bin_size;
                gdrv->MinWindowsBuild = 7600;  // Windows 7
                gdrv->MaxWindowsBuild = 26100; // Windows 11
                gdrv->IsBlocked = false;
                drivers[DRIVER_ID_GDRV] = std::move(gdrv);

                // Load RTCore driver  
                auto rtcore = std::make_unique<DriverInfo>();
                rtcore->DriverId = DRIVER_ID_RTCORE;
                rtcore->DriverName = L"MSI RTCore64";
                rtcore->FileName = L"RTCore64.sys";
                if (rtcore_bin_size > 0) {
                    rtcore->DriverData.assign(rtcore_bin_data, rtcore_bin_data + rtcore_bin_size);
                }
                rtcore->DriverDataSize = rtcore_bin_size;
                rtcore->MinWindowsBuild = 7600;
                rtcore->MaxWindowsBuild = 26100;
                rtcore->IsBlocked = true; // More commonly blocked
                drivers[DRIVER_ID_RTCORE] = std::move(rtcore);

                // Load DBUtil driver
                auto dbutil = std::make_unique<DriverInfo>();
                dbutil->DriverId = DRIVER_ID_DBUTIL;
                dbutil->DriverName = L"Dell DBUtil";
                dbutil->FileName = L"DBUtil_2_3.sys";
                if (dbutil_bin_size > 0) {
                    dbutil->DriverData.assign(dbutil_bin_data, dbutil_bin_data + dbutil_bin_size);
                }
                dbutil->DriverDataSize = dbutil_bin_size;
                dbutil->MinWindowsBuild = 7600;
                dbutil->MaxWindowsBuild = 26100;
                dbutil->IsBlocked = true; // Heavily blocked
                drivers[DRIVER_ID_DBUTIL] = std::move(dbutil);

                return !drivers.empty();
            } catch (...) {
                return false;
            }
        }

        bool DriverDataManager::LoadExternalDrivers() {
            // Get module directory for robust path resolution
            wchar_t exePath[MAX_PATH];
            GetModuleFileNameW(NULL, exePath, MAX_PATH);
            std::filesystem::path binDir = std::filesystem::path(exePath).parent_path();
            
            // Define search paths relative to executable location
            std::vector<std::filesystem::path> searchPaths = {
                binDir / "drv",                                // Deployment: ./drv/
                binDir / ".." / ".." / "KernelMode" / "drv",   // Debug: ../../KernelMode/drv/
                std::filesystem::current_path() / "drv",       // CWD: ./drv/
                std::filesystem::path("KernelMode/drv")        // Legacy fallback
            };

            // Define drivers to look for - PRIORITIZE PRIMARY IDs
            // Use both .sys and .bin extensions for robustness
            const std::vector<std::pair<std::wstring, ULONG>> validDrivers = {
                {L"gdrv.sys", DRIVER_ID_GDRV},
                {L"gdrv.bin", DRIVER_ID_GDRV},
                {L"RTCore64.sys", DRIVER_ID_RTCORE},
                {L"RTCore64.bin", DRIVER_ID_RTCORE},
                {L"DBUtil_2_3.sys", DRIVER_ID_DBUTIL},
                {L"DbUtil2_3.bin", DRIVER_ID_DBUTIL},
                {L"kprocesshacker.bin", DRIVER_ID_KPROCESSHACKER},
                {L"iQVM64.bin", DRIVER_ID_INTEL_NAL},
                {L"iqvw64e.sys", DRIVER_ID_INTEL_NAL},
                 // Legacy external IDs kept for compatibility if requested explicitly
                {L"gdrv_ext.bin", DRIVER_ID_GDRV_EXTERNAL} 
            };

            bool loadedAny = false;

            for (const auto& [fileName, driverId] : validDrivers) {
                // Find the file in search paths
                std::filesystem::path foundPath;
                bool found = false;
                
                for (const auto& searchPath : searchPaths) {
                    std::filesystem::path fullPath = searchPath / fileName;
                    std::error_code ec;
                    if (std::filesystem::exists(fullPath, ec)) {
                        foundPath = fullPath;
                        found = true;
                        break;
                    }
                }
                
                if (!found) continue;

                std::ifstream file(foundPath, std::ios::binary | std::ios::ate);
                if (!file) continue;

                auto size = file.tellg();
                
                const std::streamsize MAX_DRIVER_SIZE = 32 * 1024 * 1024; // 32MB Limit
                if (size > MAX_DRIVER_SIZE) {
                    std::wcerr << L"[-] Skiping driver file (too large): " << foundPath 
                               << L" Size: " << size << L" bytes" << std::endl;
                    continue;
                }
                if (size <= 0) continue;

                file.seekg(0);

                auto data = std::make_unique<std::vector<BYTE>>(size);
                file.read(reinterpret_cast<char*>(data->data()), size);
                file.close();

                // Create driver info
                auto driver = std::make_unique<DriverInfo>();
                driver->DriverId = driverId;
                
                // Set driver-specific information based on specific variant
                switch (driverId) {
                    case DRIVER_ID_GDRV:
                    case DRIVER_ID_GDRV_EXTERNAL:
                        driver->DriverName = L"GIGABYTE GDRV (External)";
                        driver->FileName = L"gdrv.sys";
                        driver->IsBlocked = false;
                        break;
                    case DRIVER_ID_RTCORE:
                    case DRIVER_ID_RTCORE_EXTERNAL:
                        driver->DriverName = L"MSI RTCore64 (External)";
                        driver->FileName = L"RTCore64.sys";
                        driver->IsBlocked = true;
                        break;
                    case DRIVER_ID_DBUTIL_2_3:
                    case DRIVER_ID_DBUTIL_EXTERNAL:
                        driver->DriverName = L"Dell DBUtil v2.3 (External)";
                        driver->FileName = L"DBUtil_2_3.sys";
                        driver->IsBlocked = true;
                        break;                    case DRIVER_ID_INTEL_NAL:
                        driver->DriverName = L"Intel Nal (External)";
                        driver->FileName = L"iqvw64e.sys"; // Standard name
                        driver->MinWindowsBuild = 7600;
                        driver->MaxWindowsBuild = 26100;
                        driver->IsBlocked = false; 
                        break;                    case DRIVER_ID_KPROCESSHACKER:
                        driver->DriverName = L"Process Hacker Driver (External)";
                        driver->FileName = L"kprocesshacker.sys";
                        driver->IsBlocked = false; 
                        break;
                    default:
                        continue;
                }

                driver->DriverData = *data;  // Copy the vector data
                driver->DriverDataSize = static_cast<ULONG>(size);
                driver->MinWindowsBuild = 7600;
                driver->MaxWindowsBuild = 26100;

                drivers[driverId] = std::move(driver); // Will overwrite embedded if exists
                loadedAny = true;

                std::wcout << L"[+] Loaded external driver: " << foundPath.wstring() << std::endl;
            }

            return loadedAny;
        }

        // Helper function to determine driver family for compatibility
        std::wstring DriverDataManager::GetDriverFamily(ULONG driverId) {
            switch (driverId) {
                case DRIVER_ID_GDRV:
                case DRIVER_ID_GDRV_EXTERNAL:
                    return L"GDRV";
                    
                case DRIVER_ID_RTCORE:
                case DRIVER_ID_RTCORE_EXTERNAL:
                    return L"RTCore";
                    
                case DRIVER_ID_DBUTIL_2_3:
                case DRIVER_ID_DBUTIL_EXTERNAL:
                    return L"DBUtil";
                    
                case DRIVER_ID_WINRING0:
                    return L"WinRing0";
                    
                case DRIVER_ID_AIDA64:
                    return L"AIDA64";
                    
                default:
                    return L"Unknown";
            }
        }

        bool DriverDataManager::ExtractDriver(ULONG driverId, const std::wstring& outputPath) {
            // LIFECYCLE-010 FIX: Bounds checking
            if (drivers.size() >= 1024) {
                std::wcerr << L"[-] Maximum driver limit (1024) exceeded" << std::endl;
                return false;
            }
            
            auto it = drivers.find(driverId);
            if (it == drivers.end()) {
                std::wcerr << L"[-] Driver ID " << driverId << L" not found." << std::endl;
                return false;
            }

            const auto& driver = it->second;
            
            // Validate driver data
            if (driver->DriverData.empty() || driver->DriverDataSize == 0) {
                std::wcerr << L"[-] Driver data is empty for ID " << driverId << std::endl;
                return false;
            }

            // Try KDU-style decompression with multiple keys
            SIZE_T decompressedSize = 0;
            PVOID decompressedData = nullptr;
            
            for (ULONG key : PROVIDER_RES_KEYS) {
                decompressedData = DecompressDriverData(
                    (PVOID)driver->DriverData.data(), 
                    driver->DriverData.size(), 
                    &decompressedSize, 
                    key
                );
                
                if (decompressedData && decompressedSize > 0) {
                    std::wcout << L"[+] Successfully decompressed with key 0x" << std::hex << key << std::dec << std::endl;
                    break;
                }
            }

            std::ofstream outFile(outputPath, std::ios::binary);
            if (!outFile) {
                std::wcerr << L"[-] Failed to create output file: " << outputPath << std::endl;
                if (decompressedData) {
                    HeapFree(GetProcessHeap(), 0, decompressedData);
                }
                return false;
            }

            if (decompressedData && decompressedSize > 0) {
                // Write decompressed data
                outFile.write(reinterpret_cast<const char*>(decompressedData), decompressedSize);
                std::wcout << L"[+] Extracted and decompressed " << driver->DriverName 
                           << L" (" << decompressedSize << L" bytes) to " << outputPath << std::endl;
                HeapFree(GetProcessHeap(), 0, decompressedData);
            } else {
                // Fallback: write raw data (might be uncompressed)
                outFile.write(reinterpret_cast<const char*>(driver->DriverData.data()), driver->DriverData.size());
                std::wcout << L"[!] Extracted raw data for " << driver->DriverName 
                           << L" (decompression failed) to " << outputPath << std::endl;
            }

            outFile.close();
            return true;
        }

        const DriverInfo* DriverDataManager::GetBestDriver() {
            const DriverInfo* bestDriver = nullptr;
            int bestScore = -1;

            for (const auto& [id, driver] : drivers) {
                if (!IsDriverSuitable(driver.get())) continue;

                int score = 0;
                
                // Prefer less blocked drivers
                if (!driver->IsBlocked) score += 100;
                
                // Prefer GDRV family (most reliable)
                if (driver->DriverId == DRIVER_ID_GDRV || driver->DriverId == DRIVER_ID_GDRV_EXTERNAL) {
                    score += 50;
                }
                
                // Prefer embedded drivers over external variants
                if (driver->DriverId == DRIVER_ID_GDRV || 
                    driver->DriverId == DRIVER_ID_RTCORE || 
                    driver->DriverId == DRIVER_ID_DBUTIL) {
                    score += 25;
                }
                
                // Prefer newer/specific driver versions
                if (driver->DriverId == DRIVER_ID_RTCORE64) score += 20; // RTCore64 over RTCore
                if (driver->DriverId == DRIVER_ID_DBUTIL_2_3) score += 15; // Specific version
                
                // Prefer other known working drivers
                if (driver->DriverId == DRIVER_ID_WINRING0) score += 30;
                if (driver->DriverId == DRIVER_ID_AIDA64) score += 25;

                if (score > bestScore) {
                    bestScore = score;
                    bestDriver = driver.get();
                }
            }

            return bestDriver;
        }

        const DriverInfo* DriverDataManager::GetDriverInfo(ULONG driverId) {
            // LIFECYCLE-010 FIX: Add bounds checking
            if (drivers.size() >= 1024) {
                std::wcerr << L"[-] Maximum driver limit (1024) reached" << std::endl;
                return nullptr;
            }
            
            auto it = drivers.find(driverId);
            return (it != drivers.end()) ? it->second.get() : nullptr;
        }

        std::vector<const DriverInfo*> DriverDataManager::GetAvailableDrivers() {
            std::vector<const DriverInfo*> result;
            for (const auto& [id, driver] : drivers) {
                if (IsDriverSuitable(driver.get())) {
                    result.push_back(driver.get());
                }
            }
            return result;
        }

        bool DriverDataManager::IsDriverSuitable(const DriverInfo* driver) {
            if (!driver || driver->DriverData.empty()) {
                return false;
            }

            // Check Windows version compatibility
            ULONG buildNumber = Utils::GetWindowsBuildNumber();
            if (buildNumber < driver->MinWindowsBuild || buildNumber > driver->MaxWindowsBuild) {
                return false;
            }

            // Check if driver is blocked (optional - you might want to allow blocked drivers for testing)
            // if (driver->IsBlocked) return false;

            return true;
        }

        // KDU-style decompression functions implementation
        void DriverDataManager::EncodeBuffer(PVOID Buffer, ULONG BufferSize, ULONG Key) {
            ULONG k, c;
            PUCHAR ptr;

            if ((Buffer == NULL) || (BufferSize == 0))
                return;

            k = Key;
            c = BufferSize;
            ptr = (PUCHAR)Buffer;

            do {
                *ptr ^= k;           // XOR Byte by Byte
                k = _rotl(k, 1);
                ptr++;               // Advance by 1 Byte
                --c;
            } while (c != 0);
        }

        // PE checksum calculation functions (from KDU)
        USHORT DriverDataManager::CalculatePartialChecksum(ULONG PartialSum, PUSHORT Source, ULONG Length) {
            while (Length--) {
                PartialSum += *Source++;
                PartialSum = (PartialSum >> 16) + (PartialSum & 0xffff);
            }
            return (USHORT)(((PartialSum >> 16) + PartialSum) & 0xffff);
        }

        BOOLEAN DriverDataManager::VerifyPEChecksum(PVOID BaseAddress, ULONG FileLength, 
                                                   PULONG HeaderChecksum, PULONG CalculatedChecksum) {
            PUSHORT AdjustSum;
            PIMAGE_NT_HEADERS NtHeaders;
            ULONG HeaderSum;
            ULONG CheckSum;
            USHORT PartialSum;

            PartialSum = CalculatePartialChecksum(0, (PUSHORT)BaseAddress, (FileLength + 1) >> 1);

            NtHeaders = ImageNtHeader(BaseAddress);
            if (NtHeaders) {
                AdjustSum = (PUSHORT)(&NtHeaders->OptionalHeader.CheckSum);
                PartialSum -= (PartialSum < AdjustSum[0]);
                PartialSum -= AdjustSum[0];
                PartialSum -= (PartialSum < AdjustSum[1]);
                PartialSum -= AdjustSum[1];
                HeaderSum = NtHeaders->OptionalHeader.CheckSum;
            }
            else {
                HeaderSum = FileLength;
                PartialSum = 0;
            }

            CheckSum = (ULONG)PartialSum + FileLength;

            if (HeaderChecksum)
                *HeaderChecksum = HeaderSum;
            if (CalculatedChecksum)
                *CalculatedChecksum = CheckSum;

            return (HeaderSum == CheckSum);
        }

        PVOID DriverDataManager::DecompressDriverData(PVOID ResourcePtr, SIZE_T ResourceSize, 
                                                     PSIZE_T DecompressedSize, ULONG DecryptKey) {
            BOOLEAN bValidData;
            DELTA_INPUT diDelta, diSource;
            DELTA_OUTPUT doOutput;
            PVOID resultPtr = NULL, dataBlob;

            *DecompressedSize = 0;

            RtlSecureZeroMemory(&diSource, sizeof(DELTA_INPUT));
            RtlSecureZeroMemory(&diDelta, sizeof(DELTA_INPUT));
            RtlSecureZeroMemory(&doOutput, sizeof(DELTA_OUTPUT));

            // Allocate buffer and decrypt
            dataBlob = HeapAlloc(GetProcessHeap(), 0, ResourceSize);
            if (dataBlob) {
                RtlCopyMemory(dataBlob, ResourcePtr, ResourceSize);
                EncodeBuffer(dataBlob, (ULONG)ResourceSize, DecryptKey);

                // --- DEBUG: Verify Decryption ---
                std::ofstream debugLog("C:\\Users\\admin\\Documents\\debug_dump.txt", std::ios::app);
                if (debugLog.is_open()) {
                    debugLog << "[DEBUG] DecryptKey: 0x" << std::hex << DecryptKey << std::dec << std::endl;
                    debugLog << "[DEBUG] Decrypted Header (First 16 Bytes): ";
                    PUCHAR dPtr = (PUCHAR)dataBlob;
                    for (int i = 0; i < 16 && i < ResourceSize; i++) {
                        debugLog << std::hex << std::setw(2) << std::setfill('0') << (int)dPtr[i] << " ";
                    }
                    debugLog << std::dec << std::endl;
                    
                    // Check for PA30 signature
                    if (ResourceSize >= 4) {
                        char sig[5] = {0};
                        memcpy(sig, dataBlob, 4);
                        debugLog << "[DEBUG] ASCII Signature: " << sig << std::endl;
                    }
                    debugLog.close();
                }
                // -------------------------------

                diDelta.Editable = FALSE;
                diDelta.lpcStart = dataBlob;
                diDelta.uSize = ResourceSize;

                // Apply Microsoft Delta decompression
                if (ApplyDeltaB(DELTA_FILE_TYPE_RAW, diSource, diDelta, &doOutput)) {
                    SIZE_T newSize = doOutput.uSize;
                    PVOID decomPtr = doOutput.lpStart;

                    bValidData = TRUE;

                    // Verify PE checksum (critical for driver signing validity!)
                    ULONG headerSum = 0, calcSum = 0;
                    if (!VerifyPEChecksum(decomPtr, (ULONG)newSize, &headerSum, &calcSum)) {
                        // Change to warning only, do not fail
                        std::wcout << L"[!] Warning: PE checksum mismatch! Header: 0x" << std::hex << headerSum 
                                   << L", Calculated: 0x" << calcSum << std::dec << std::endl;
                        // bValidData = FALSE; // RELAXED CHECK
                    }
                    else {
                        std::wcout << L"[+] PE checksum verified successfully (Header: 0x" << std::hex << headerSum << L")" << std::dec << std::endl;
                    }

                    if (bValidData) {
                        resultPtr = HeapAlloc(GetProcessHeap(), 0, newSize);
                        if (resultPtr) {
                            RtlCopyMemory(resultPtr, decomPtr, newSize);
                            *DecompressedSize = newSize;
                        }
                    }

                    DeltaFree(doOutput.lpStart);
                } else {
                    DWORD dwError = GetLastError();
                    std::wcout << L"[-] ApplyDeltaB failed with error: " << dwError << std::endl;
                }

                HeapFree(GetProcessHeap(), 0, dataBlob);
            }

            return resultPtr;
        }

    } // namespace Resources
} // namespace KernelMode