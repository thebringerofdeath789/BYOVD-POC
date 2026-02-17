/**
 * @file DriverDataManager.h
 * @author Gregory King  
 * @date August 14, 2025
 * @brief This file contains the DriverDataManager class for handling embedded driver resources.
 *
 * Manages embedded .bin driver files using KDU-style resource system with
 * support for multiple driver variants and automatic selection.
 */

#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <memory>
#include <map>

namespace KernelMode {
    namespace Resources {

        /**
         * @struct DriverInfo
         * @brief Contains information about an embedded driver.
         */
        struct DriverInfo {
            ULONG DriverId;
            std::wstring DriverName;
            std::wstring FileName;
            const BYTE* DriverData;
            ULONG DriverDataSize;
            ULONG MinWindowsBuild;
            ULONG MaxWindowsBuild;
            bool IsBlocked;
        };

        /**
         * @class DriverDataManager  
         * @brief Manages embedded driver resources in KDU style.
         *
         * This class handles extraction and management of driver .bin files
         * embedded as resources, mimicking KDU's Tanikaze/TaiGei system.
         */
        class DriverDataManager {
        public:
            /**
             * @brief Gets the singleton instance.
             * @return Reference to the singleton instance.
             */
            static DriverDataManager& GetInstance();

            /**
             * @brief Initializes the driver data system.
             * @return True if initialization succeeds, false otherwise.
             */
            bool Initialize();

            /**
             * @brief Extracts a driver by ID to a temporary file.
             * @param driverId The unique driver identifier.
             * @param outputPath Path where the driver should be extracted.
             * @return True if extraction succeeds, false otherwise.
             */
            bool ExtractDriver(ULONG driverId, const std::wstring& outputPath);

            /**
             * @brief Gets the best available driver for the current system.
             * @return Pointer to DriverInfo for the most suitable driver, or nullptr.
             */
            const DriverInfo* GetBestDriver();

            /**
             * @brief Gets driver information by ID.
             * @param driverId The driver ID to look up.
             * @return Pointer to DriverInfo, or nullptr if not found.
             */
            const DriverInfo* GetDriverInfo(ULONG driverId);

            /**
             * @brief Lists all available drivers.
             * @return Vector of all available driver information.
             */
            std::vector<const DriverInfo*> GetAvailableDrivers();

            /**
             * @brief Gets the driver family name for a given driver ID.
             * @param driverId The driver ID to check.
             * @return The driver family name (e.g., "GDRV", "RTCore", "DBUtil").
             */
            std::wstring GetDriverFamily(ULONG driverId);

        private:
            DriverDataManager() = default;
            ~DriverDataManager() = default;
            DriverDataManager(const DriverDataManager&) = delete;
            DriverDataManager& operator=(const DriverDataManager&) = delete;

            /**
             * @brief Loads embedded driver data from resources.
             * @return True if loading succeeds, false otherwise.
             */
            bool LoadEmbeddedDrivers();

            /**
             * @brief Loads driver data from external files (fallback).
             * @return True if loading succeeds, false otherwise.
             */
            bool LoadExternalDrivers();

            /**
             * @brief Checks if a driver is suitable for the current system.
             * @param driver Pointer to the driver info to check.
             * @return True if the driver is suitable, false otherwise.
             */
            bool IsDriverSuitable(const DriverInfo* driver);

            std::map<ULONG, std::unique_ptr<DriverInfo>> drivers;
            bool initialized;
        };

        // Driver IDs (expanded to handle multiple variants)
        // GDRV variants
        constexpr ULONG DRIVER_ID_GDRV = 1;
        constexpr ULONG DRIVER_ID_GDRV_EXTERNAL = 2;
        
        // RTCore variants  
        constexpr ULONG DRIVER_ID_RTCORE = 3;
        constexpr ULONG DRIVER_ID_RTCORE64 = 4;
        constexpr ULONG DRIVER_ID_RTCORE64_EXTERNAL = 5;
        
        // DBUtil variants
        constexpr ULONG DRIVER_ID_DBUTIL = 6;
        constexpr ULONG DRIVER_ID_DBUTIL_2_3 = 7;
        constexpr ULONG DRIVER_ID_DBUTIL_EXTERNAL = 8;
        
        // Other drivers
        constexpr ULONG DRIVER_ID_WINRING0 = 9;
        constexpr ULONG DRIVER_ID_AIDA64 = 10;
        
        // Legacy compatibility (for backward compatibility)
        constexpr ULONG DRIVER_ID_RTCORE_LEGACY = DRIVER_ID_RTCORE;
        constexpr ULONG DRIVER_ID_DBUTIL_LEGACY = DRIVER_ID_DBUTIL;

    } // namespace Resources
} // namespace KernelMode