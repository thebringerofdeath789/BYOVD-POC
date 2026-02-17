/**
 * @file DriverDataManager.h
 * @author Gregory King  
 * @date August 14, 2025
 * @brief This file contains the DriverDataManager class for handling embedded driver resources.
 *
 * Manages driver .bin files using KDU-style resource system with support for the complete
 * collection of vulnerable drivers found in data/ and Drv/ directories.
 */

#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <msdelta.h>

#pragma comment(lib, "msdelta.lib")

namespace KernelMode {
    namespace Resources {

        /**
         * @struct DriverInfo
         * @brief Contains information about a vulnerable driver.
         */
        struct DriverInfo {
            ULONG DriverId;
            std::wstring DriverName;
            std::wstring FileName;
            std::vector<BYTE> DriverData;
            ULONG DriverDataSize;
            ULONG MinWindowsBuild;
            ULONG MaxWindowsBuild;
            bool IsBlocked;
            std::wstring SourcePath;
            std::wstring CVE;
            std::wstring Description;
            int ReliabilityScore;  // Higher = more reliable
        };

        /**
         * @class DriverDataManager  
         * @brief Manages driver resources in KDU style with comprehensive driver support.
         */
        class DriverDataManager {
        public:
            static DriverDataManager& GetInstance();
            bool Initialize();
            bool ExtractDriver(ULONG driverId, const std::wstring& outputPath);
            const DriverInfo* GetBestDriver();
            const DriverInfo* GetDriverInfo(ULONG driverId);
            std::vector<const DriverInfo*> GetAvailableDrivers();
            void ListAllDrivers();

            // KDU-style decompression functions
            static PVOID DecompressDriverData(PVOID ResourcePtr, SIZE_T ResourceSize, 
                                            PSIZE_T DecompressedSize, ULONG DecryptKey);
            static void EncodeBuffer(PVOID Buffer, ULONG BufferSize, ULONG Key);

        private:
            // Actual KDU decryption key from KDU source code
            static constexpr ULONG PROVIDER_RES_KEY = 0xF62E6CE0;
            
            // Additional keys to try as fallback (different KDU versions)
            static constexpr ULONG PROVIDER_RES_KEYS[] = { 
                0x0783C1E0,  // KDU v2025? (Found via crypto-analysis)
                0x70E0DD63,  // KDU v11.3+
                0x1eac9953,  // KDU v10/v11
                0xd4c20412,  // KDU v7/v8
                0xF62E6CE0,  // Official KDU key from source
                0x10030F0F,  // Alternative key  
                0x30303030,  // Common pattern
                0x0F0F0F0F,  // Simple pattern
                0x12345678,  // Test key
                0x00000000   // No encryption
            };

        private:
            DriverDataManager() = default;
            ~DriverDataManager() = default;
            DriverDataManager(const DriverDataManager&) = delete;
            DriverDataManager& operator=(const DriverDataManager&) = delete;

            bool LoadExternalDrivers();
            bool LoadDriverFromFile(const std::wstring& filePath, ULONG driverId, const std::wstring& driverName, 
                                  const std::wstring& cve, const std::wstring& description, int reliabilityScore, bool isBlocked);
            bool IsDriverSuitable(const DriverInfo* driver);
            ULONG GetWindowsBuildNumber();

            std::map<ULONG, std::unique_ptr<DriverInfo>> drivers;
            bool initialized = false;
        };

        // Comprehensive Driver IDs based on your .bin files
        // Tier 1 - Most Reliable (Low Detection)
        constexpr ULONG DRIVER_ID_GDRV = 1;
        constexpr ULONG DRIVER_ID_WINRING0 = 2;
        constexpr ULONG DRIVER_ID_HWINFO64 = 3;
        constexpr ULONG DRIVER_ID_MSIO64 = 4;
        constexpr ULONG DRIVER_ID_AIDA64 = 5;

        // Tier 2 - Good Reliability 
        constexpr ULONG DRIVER_ID_DIRECTIO64 = 10;
        constexpr ULONG DRIVER_ID_GLCKIO2 = 11;
        constexpr ULONG DRIVER_ID_ENEIO64 = 12;
        constexpr ULONG DRIVER_ID_ASIO2 = 13;
        constexpr ULONG DRIVER_ID_ASIO3 = 14;

        // Tier 3 - Moderate Reliability
        constexpr ULONG DRIVER_ID_RTCORE64 = 20;
        constexpr ULONG DRIVER_ID_DBUTIL = 21;
        constexpr ULONG DRIVER_ID_PHYSMEM = 22;
        constexpr ULONG DRIVER_ID_PHYMEMX64 = 23;

        // Tier 4 - Specialized/Process Tools
        constexpr ULONG DRIVER_ID_PROCEXP = 30;
        constexpr ULONG DRIVER_ID_KPROCESSHACKER = 31;
        constexpr ULONG DRIVER_ID_MIMIDRV = 32;
        constexpr ULONG DRIVER_ID_DBK64 = 33;

        // Tier 5 - Vendor Specific (Higher Detection Risk)
        constexpr ULONG DRIVER_ID_ALSYSIO64 = 40;
        constexpr ULONG DRIVER_ID_AMDRYZEN = 41;
        constexpr ULONG DRIVER_ID_ASRDRV = 42;
        constexpr ULONG DRIVER_ID_APPSHOP = 43;
        constexpr ULONG DRIVER_ID_AMSDK = 44;

    } // namespace Resources
} // namespace KernelMode
