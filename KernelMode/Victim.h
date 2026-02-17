#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include "ServiceManager.h"

namespace KernelMode {

    class Victim {
    public:
        Victim(const std::wstring& driverPath, const std::wstring& deviceName);
        ~Victim();

        // Loads the victim driver using ServiceManager
        bool Load();

        // Unloads the victim driver
        bool Unload();

        // Returns the kernel base address of the loaded driver
        uintptr_t GetBaseAddress() const;

        // Returns the size of the loaded image
        uint32_t GetImageSize() const;

        // Returns the name of the device object (e.g. L"\\Device\\ProcExp152")
        std::wstring GetDeviceName() const;

        // Returns the name of the driver service
        std::wstring GetDriverName() const;

        // Validates if the victim is suitable (e.g. checking specific exports or patterns)
        bool Validate() const;

    private:
        std::wstring driverPath;
        std::wstring driverName; // derived from path
        std::wstring deviceName;
        std::shared_ptr<ServiceManager> serviceManager;
        uintptr_t baseAddress;
        uint32_t imageSize;
        bool loaded;

        // Calculate kernel module information
        void ResolveModuleInfo();
    };

}
