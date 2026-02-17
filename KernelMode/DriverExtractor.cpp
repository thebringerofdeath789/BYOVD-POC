/**
 * @file DriverExtractor.cpp
 * @author Gregory King
 * @date September 8, 2025
 * @brief Implementation of DriverExtractor class for converting .bin files to .sys drivers
 */

#include "DriverExtractor.h"
#include "DriverDataManager.h"
#include <iostream>
#include <filesystem>

namespace KernelMode {

    DriverExtractor::DriverExtractor() {
        // Initialize drivers path to current directory
        wchar_t currentPath[MAX_PATH];
        GetCurrentDirectoryW(MAX_PATH, currentPath);
        driversPath = std::wstring(currentPath) + L"\\drv\\";
    }

    DriverExtractor::~DriverExtractor() {
        // Cleanup is handled by individual driver cleanup calls
    }

    bool DriverExtractor::ExtractDriver(const std::wstring& binPath, const std::wstring& sysPath) {
        // Simple extraction - just copy the .bin file to .sys
        // Real KDU implementation would handle decompression and signing verification
        
        if (!ValidatePE(binPath)) {
            std::wcerr << L"[-] Invalid PE file: " << binPath << std::endl;
            return false;
        }
        
        return CopyBinToSys(binPath, sysPath);
    }

    std::vector<DriverInfo> DriverExtractor::GetAvailableDrivers() {
        std::vector<DriverInfo> availableDrivers;
        
        // Define known driver mappings
        std::vector<DriverInfo> knownDrivers = {
            {L"gdrv.bin", L"gdrv.sys", L"GDRV", L"CVE-2018-19320", false},
            {L"RTCore64.bin", L"RTCore64.sys", L"RTCore64", L"CVE-2019-16098", false},
            {L"DBUtil_2_3.bin", L"DBUtil_2_3.sys", L"DBUtil", L"CVE-2021-21551", false}
        };
        
        // Check which drivers are actually available
        for (auto& driver : knownDrivers) {
            std::wstring fullPath = driversPath + driver.binFile;
            if (std::filesystem::exists(fullPath)) {
                driver.isAvailable = true;
                availableDrivers.push_back(driver);
            }
        }
        
        return availableDrivers;
    }

    std::wstring DriverExtractor::PrepareDriver(const std::wstring& driverName) {
        // Use DriverDataManager to extract the driver
        auto& manager = Resources::DriverDataManager::GetInstance();
        if (!manager.Initialize()) {
            return L"";
        }
        
        // Get driver info by name
        const Resources::DriverInfo* driverInfo = nullptr;
        for (const auto* info : manager.GetAvailableDrivers()) {
            if (info->DriverName.find(driverName) != std::wstring::npos) {
                driverInfo = info;
                break;
            }
        }
        
        if (!driverInfo) {
            std::wcerr << L"[-] Driver not found: " << driverName << std::endl;
            return L"";
        }
        
        // Extract to temporary location
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        std::wstring sysPath = std::wstring(tempPath) + driverInfo->FileName;
        
        if (manager.ExtractDriver(driverInfo->DriverId, sysPath)) {
            return sysPath;
        }
        
        return L"";
    }

    void DriverExtractor::CleanupDriver(const std::wstring& sysPath) {
        if (!sysPath.empty()) {
            DeleteFileW(sysPath.c_str());
        }
    }

    bool DriverExtractor::ValidatePE(const std::wstring& binPath) {
        // Simple PE validation - check for MZ signature
        HANDLE hFile = CreateFileW(binPath.c_str(), GENERIC_READ, FILE_SHARE_READ, 
                                   nullptr, OPEN_EXISTING, 0, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            return false;
        }
        
        IMAGE_DOS_HEADER dosHeader;
        DWORD bytesRead;
        BOOL result = ReadFile(hFile, &dosHeader, sizeof(dosHeader), &bytesRead, nullptr);
        CloseHandle(hFile);
        
        return result && bytesRead == sizeof(dosHeader) && dosHeader.e_magic == IMAGE_DOS_SIGNATURE;
    }

    bool DriverExtractor::CopyBinToSys(const std::wstring& source, const std::wstring& destination) {
        return CopyFileW(source.c_str(), destination.c_str(), FALSE) != 0;
    }

} // namespace KernelMode
