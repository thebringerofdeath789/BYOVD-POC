/**
 * @file DriverExtractor.h
 * @author Gregory King
 * @date September 8, 2025
 * @brief Driver extractor for converting embedded .bin files to working .sys drivers
 *
 * This class mimics KDU's driver extraction functionality, taking embedded
 * signed driver binaries and creating working .sys files that can be loaded
 * by the Windows service manager.
 */

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <fstream>

namespace KernelMode {
    
    struct DriverInfo {
        std::wstring binFile;      // Source .bin file (e.g., "gdrv.bin")
        std::wstring sysFile;      // Target .sys file (e.g., "gdrv.sys")
        std::wstring driverName;   // Service name
        std::wstring cve;          // CVE identifier
        bool isAvailable;          // Whether the .bin file exists
    };
    
    class DriverExtractor {
    public:
        DriverExtractor();
        ~DriverExtractor();
        
        /**
         * @brief Extracts a driver from .bin to .sys format
         * @param binPath Path to the embedded .bin file
         * @param sysPath Path where to create the .sys file
         * @return True if extraction successful, false otherwise
         */
        bool ExtractDriver(const std::wstring& binPath, const std::wstring& sysPath);
        
        /**
         * @brief Gets list of available drivers that can be extracted
         * @return Vector of DriverInfo structures
         */
        std::vector<DriverInfo> GetAvailableDrivers();
        
        /**
         * @brief Attempts to extract and prepare a specific driver
         * @param driverName Name of the driver (e.g., "gdrv", "RTCore64")
         * @return Path to the extracted .sys file, or empty string if failed
         */
        std::wstring PrepareDriver(const std::wstring& driverName);
        
        /**
         * @brief Cleans up extracted driver files
         * @param sysPath Path to the .sys file to remove
         */
        void CleanupDriver(const std::wstring& sysPath);
        
    private:
        std::wstring driversPath;  // Path to the drv/ folder
        
        /**
         * @brief Validates that a .bin file contains a valid PE
         * @param binPath Path to the .bin file
         * @return True if valid PE, false otherwise
         */
        bool ValidatePE(const std::wstring& binPath);
        
        /**
         * @brief Copies .bin file to .sys file with proper permissions
         * @param source Source .bin file
         * @param destination Target .sys file
         * @return True if copy successful, false otherwise
         */
        bool CopyBinToSys(const std::wstring& source, const std::wstring& destination);
    };
}
