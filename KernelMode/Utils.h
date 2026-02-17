/**
 * @file Utils.h
 * @author Gregory King
 * @date August 13, 2025
 * @brief This file contains the declaration of the Utils namespace.
 *
 * The Utils namespace provides a collection of helper functions for
 * interacting with the Windows kernel and drivers. This includes
 * functionalities like managing services (drivers), retrieving kernel
 * module information, and other common tasks required by the toolkit.
 */

#pragma once

#include <windows.h>
#include <string>
#include <cstdint>

namespace KernelMode {
    namespace Providers {
        class IProvider;
    }

    namespace Utils {
        struct ModuleInfo {
            uintptr_t BaseAddress;
            uint32_t ImageSize;
        };

        /**
         * @brief Gets the base address and size of a kernel module.
         * @param moduleName The name of the kernel module (e.g., "ntoskrnl.exe").
         * @return ModuleInfo struct containing base and size.
         */
        ModuleInfo GetKernelModuleInfo(const std::string& moduleName);

        /**
         * @brief Gets the base address of a kernel module.
         * @param moduleName The name of the kernel module (e.g., "ntoskrnl.exe").
         * @return The base address of the module, or 0 if not found.
         */
        uintptr_t GetKernelModuleBase(const std::string& moduleName);

        /**
         * @brief Gets the address of an exported function from a kernel module.
         * @param moduleBase The base address of the kernel module.
         * @param functionName The name of the function to find.
         * @param moduleName The name of the module (e.g., "ntoskrnl.exe", "ci.dll"). Defaults to "ntoskrnl.exe".
         * @return The address of the function, or 0 if not found.
         */
        uintptr_t GetKernelExport(uintptr_t moduleBase, const std::string& functionName, const std::string& moduleName = "ntoskrnl.exe");

        /**
         * @brief Gets the kernel object address for a given handle.
         * @param handle Open handle to the object.
         * @return The kernel address of the object, or 0 on failure.
         */
        uintptr_t GetKernelObjectAddress(HANDLE handle);

        /**
         * @brief Creating and starting a Windows service for a driver.
         * @param serviceName The desired name for the service.
         * @param driverPath The full path to the driver file.
         * @return A handle to the service, or nullptr on failure.
         */
        SC_HANDLE CreateDriverService(const std::wstring& serviceName, const std::wstring& driverPath);

        /**
         * @brief Stops and deletes a Windows service.
         * @param serviceHandle A handle to the service to remove.
         * @return True if the service was stopped and deleted, false otherwise.
         */
        bool RemoveDriverService(SC_HANDLE serviceHandle);

        /**
         * @brief Gets the Windows build number.
         * @return The Windows build number, or 0 if unable to retrieve.
         */
        ULONG GetWindowsBuildNumber();

        /**
         * @brief Scans memory for a byte pattern with optional masking.
         * @param data Pointer to the memory to scan.
         * @param dataSize Size of the memory to scan.
         * @param pattern Byte pattern to search for.
         * @param patternSize Size of the pattern.
         * @param mask Mask string ('x' = match, '?' = wildcard), or nullptr for exact match.
         * @return Offset of the pattern within data, or SIZE_MAX if not found.
         */
        size_t FindPattern(const void* data, size_t dataSize, const void* pattern, size_t patternSize, const char* mask = nullptr);

        /**
         * @brief Finds g_CiOptions address using KDU-style pattern scanning.
         * @param ciModuleBase Base address of ci.dll module.
         * @param ciModuleSize Size of ci.dll module.
         * @return Virtual address of g_CiOptions, or 0 if not found.
         */
        uintptr_t FindCiOptionsAddress(uintptr_t ciModuleBase, size_t ciModuleSize);

        /**
         * @brief Loads a kernel module (like ci.dll) for pattern scanning.
         * @param moduleName Name of the module to load (e.g., "ci.dll").
         * @return HMODULE handle to the loaded module, or nullptr on failure.
         */
        HMODULE LoadKernelModule(const std::wstring& moduleName);

        // ============================================================================
        // Authentic KDU Page Table Walking Functions
        // ============================================================================

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
        int PageTableEntryToPhysicalAddress(ULONG_PTR entry, ULONG_PTR* phyaddr);

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
            _Out_ ULONG_PTR* physicalAddress);

        /**
         * @brief Find PML4 value from low stub memory (authentic KDU implementation)
         * @param lowStub1M Pointer to mapped low 1MB memory
         * @return PML4 value or 0 if not found
         */
        ULONG_PTR GetPML4FromLowStub1M(ULONG_PTR lowStub1M);

        /**
         * @brief Virtual to Physical translation using an IProvider for memory access.
         * @param provider The provider to use for physical memory reads.
         * @param virtualAddress The virtual address to translate.
         * @return The physical address, or 0 on failure.
         */
        uintptr_t VirtualToPhysical(Providers::IProvider* provider, uintptr_t virtualAddress);

        /**
         * @brief Patches g_CiOptions using the given provider to bypass DSE.
         * @param provider The provider to use for memory writing.
         * @return True if successful, false otherwise.
         */
        bool PatchCiOptions(Providers::IProvider* provider);
    }
}