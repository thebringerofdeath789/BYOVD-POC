#include "Victim.h"
#include "Utils.h"
#include <filesystem>
#include <iostream>

namespace KernelMode {

    Victim::Victim(const std::wstring& driverPath, const std::wstring& deviceName)
        : driverPath(driverPath), deviceName(deviceName), baseAddress(0), imageSize(0), loaded(false) {
        
        // Extract filename from path for the service name
        std::filesystem::path p(driverPath);
        this->driverName = p.stem().wstring();
        
        // Initialize ServiceManager with the derived name
        this->serviceManager = std::make_shared<ServiceManager>(this->driverName);
    }

    Victim::~Victim() {
        if (loaded) {
            Unload();
        }
    }

    bool Victim::Load() {
        // 1. Install Service
        ServiceInfo info = serviceManager->InstallDriverService(driverName, driverPath, driverName);
        if (info.status == ServiceStatus::ERROR_STATE) {
            std::wcerr << L"[-] Failed to install service for victim driver: " << driverName << std::endl;
             // If it exists, might be okay
        }

        // 2. Start Service
        if (serviceManager->StartDriverService(driverName)) {
            std::wcout << L"[+] Victim driver service started: " << driverName << std::endl;
            loaded = true;
            
            // --- BUG-H014 FIX: Poll for module with exponential backoff ---
            // Service start is asynchronous, driver may not be loaded immediately
            std::wcout << L"[*] Waiting for driver to load in kernel..." << std::endl;
            const int MAX_RETRIES = 50;
            bool resolved = false;
            for (int retry = 0; retry < MAX_RETRIES; ++retry) {
                ResolveModuleInfo();
                if (baseAddress != 0) {
                    resolved = true;
                    std::wcout << L"[+] Driver module resolved after " << retry << L" retries" << std::endl;
                    break;
                }
                // Exponential backoff: 10ms, 20ms, 40ms, ..., max 500ms
                DWORD sleepTime = min(10 * (1 << retry), 500);
                Sleep(sleepTime);
            }
            
            if (!resolved) {
                std::wcerr << L"[-] Failed to resolve driver module after " << MAX_RETRIES << L" retries" << std::endl;
                std::wcerr << L"[-] Driver may still be loading or failed to load" << std::endl;
            }
            // ----------------------------------------------------------------
            
            return true;
        } else {
             std::wcout << L"[-] Failed to start victim driver service." << std::endl;
        }
        
        return false;
    }

    bool Victim::Unload() {
        // --- BUG-M020 FIX: Set loaded = false at start to prevent double-unload ---
        loaded = false; // Set before cleanup to prevent destructor from re-calling
        // -------------------------------------------------------------------------
        
        if (serviceManager->StopAndDeleteService(driverName)) {
            baseAddress = 0;
            imageSize = 0;
            return true;
        }
        return false; // Still return false on failure, but loaded already set
    }

    void Victim::ResolveModuleInfo() {
        // Convert driver name to string for Utils
        std::filesystem::path p(driverPath);
        std::string moduleName = p.filename().string();

        auto info = Utils::GetKernelModuleInfo(moduleName);
        if (info.BaseAddress != 0) {
            baseAddress = info.BaseAddress;
            imageSize = info.ImageSize;
            std::cout << "[+] Resolved Victim Base: 0x" << std::hex << baseAddress << ", Size: 0x" << imageSize << std::dec << std::endl;
        } else {
            std::cerr << "[-] Failed to resolve loaded victim driver address: " << moduleName << std::endl;
        }
    }

    uintptr_t Victim::GetBaseAddress() const { return baseAddress; }
    uint32_t Victim::GetImageSize() const { return imageSize; }
    std::wstring Victim::GetDeviceName() const { return deviceName; }
    std::wstring Victim::GetDriverName() const { return driverName; }

    bool Victim::Validate() const {
        return baseAddress != 0 && imageSize > 0;
    }

}
