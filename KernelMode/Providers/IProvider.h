/**
 * @file IProvider.h
 * @author Gregory King
 * @date September 7, 2025
 * @brief Enhanced IProvider interface with KDU/Hamakaze-style capabilities.
 */

#pragma once

#include <memory>
#include <string>
#include <Windows.h>
#include <winternl.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

// IOCTL codes for various providers
// IOCTL Definitions for various drivers can be placed here or in specific provider headers
// #define IOCTL_RTCORE_READ_MEMORY ... (Removed: Incorrect definition)
#define IOCTL_RTCORE_WRITE_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DBUTIL_MAP_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x9B0C1EC4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DBUTIL_UNMAP_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x9B0C1EC8, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GDRV_READ_MEMORY 0x9876C004
#define IOCTL_GDRV_WRITE_MEMORY 0x9876C008

namespace KernelMode {
    namespace Providers {

        /**
         * @enum ProviderCapabilities
         * @brief KDU-style provider capability flags
         */
        enum ProviderCapabilities {
            CAPABILITY_NONE = 0x00,
            CAPABILITY_PHYSICAL_MEMORY = 0x01,      // Can access physical memory directly
            CAPABILITY_VIRTUAL_MEMORY = 0x02,       // Can access virtual memory directly
            CAPABILITY_DSE_BYPASS = 0x04,           // Can bypass Driver Signature Enforcement
            CAPABILITY_PML4_LOWSTUB = 0x08,         // Can access PML4 from low stub
            CAPABILITY_PHYSICAL_BRUTEFORCE = 0x10,  // Can use physical memory brute force
            CAPABILITY_PREFER_PHYSICAL = 0x20,      // Prefers physical memory access
            CAPABILITY_SHELLCODE_INJECTION = 0x40   // Can inject shellcode into drivers
        };

        /**
         * @enum ProviderStatus
         * @brief Comprehensive status codes for provider operations
         */
        enum ProviderStatus {
            PROVIDER_SUCCESS = 0x00000000,                    // Operation completed successfully
            PROVIDER_ERROR_INVALID_HANDLE = 0xC0000008,       // Invalid device handle
            PROVIDER_ERROR_ACCESS_DENIED = 0xC0000022,        // Access denied
            PROVIDER_ERROR_INVALID_PARAMETER = 0xC000000D,    // Invalid parameter
            PROVIDER_ERROR_NOT_SUPPORTED = 0xC00000BB,        // Operation not supported
            PROVIDER_ERROR_DEVICE_NOT_READY = 0xC00000A3,     // Device not ready
            PROVIDER_ERROR_INSUFFICIENT_RESOURCES = 0xC000009A, // Insufficient resources
            PROVIDER_ERROR_MEMORY_ALLOCATION = 0xC0000017,    // Memory allocation failed
            PROVIDER_ERROR_DRIVER_LOAD_FAILED = 0xC0000263,   // Driver loading failed
            PROVIDER_ERROR_SERVICE_CREATE_FAILED = 0xC0000001, // Service creation failed
            PROVIDER_ERROR_DSE_BYPASS_FAILED = 0xC0000002,    // DSE bypass failed
            PROVIDER_ERROR_PATTERN_NOT_FOUND = 0xC0000003,    // Pattern scanning failed
            PROVIDER_ERROR_INVALID_ADDRESS = 0xC0000004,      // Invalid memory address
            PROVIDER_ERROR_READ_FAILED = 0xC0000005,          // Memory read operation failed
            PROVIDER_ERROR_WRITE_FAILED = 0xC0000006,         // Memory write operation failed
            PROVIDER_ERROR_SHELLCODE_EXEC_FAILED = 0xC0000007, // Shellcode execution failed
            PROVIDER_ERROR_THREAD_CREATE_FAILED = 0xC0000008, // Thread creation failed
            PROVIDER_ERROR_UNKNOWN = 0xC0000001              // Unknown error
        };

        /**
         * @struct ProviderLoadData
         * @brief KDU-style provider configuration data
         */
        struct ProviderLoadData {
            bool PhysMemoryBruteForce;     // Uses physical memory brute force
            bool PML4FromLowStub;          // Uses PML4 from low stub
            bool PreferPhysical;           // Prefers physical access methods
            bool RequiresDSE;              // Requires DSE bypass to function
            ULONG Capabilities;            // Combined capability flags
            const wchar_t* Description;   // Human-readable description
        };

        /**
         * @class IProvider
         * @brief Enhanced interface for kernel memory access providers with KDU-style capabilities.
         */
        class IProvider {
        public:
            virtual ~IProvider() = default;

            /**
             * @brief Initializes the provider with a specific driver ID and optional DSE bypass.
             * @param driverId The driver ID to use (0 = auto-select best driver).
             * @param bypassDSE Whether to attempt DSE bypass before loading.
             * @return True if initialization succeeds, false otherwise.
             */
            virtual bool Initialize(ULONG driverId = 0, bool bypassDSE = false) = 0;

            /**
             * @brief Deinitializes the provider and cleans up resources.
             */
            virtual void Deinitialize() = 0;

            /**
             * @brief Gets the name of this provider for logging/display purposes.
             * @return The provider name as a wide string.
             */
            virtual std::wstring GetProviderName() const = 0;

            /**
             * @brief Reads kernel memory using the most appropriate method.
             * @param address The kernel virtual address to read from.
             * @param buffer Buffer to store the read data.
             * @param size Number of bytes to read.
             * @return True if the read succeeds, false otherwise.
             */
            virtual bool ReadKernelMemory(uintptr_t address, void* buffer, size_t size) = 0;

            /**
             * @brief Writes kernel memory using the most appropriate method.
             * @param address The kernel virtual address to write to.
             * @param buffer Buffer containing data to write.
             * @param size Number of bytes to write.
             * @return True if the write succeeds, false otherwise.
             */
            virtual bool WriteKernelMemory(uintptr_t address, void* buffer, size_t size) = 0;

            /**
             * @brief Reads physical memory directly (if supported).
             * @param physicalAddress The physical address to read from.
             * @param buffer Buffer to store the read data.
             * @param size Number of bytes to read.
             * @return True if the read succeeds, false otherwise.
             */
            virtual bool ReadPhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) = 0;

            /**
             * @brief Writes physical memory directly (if supported).
             * @param physicalAddress The physical address to write to.
             * @param buffer Buffer containing data to write.
             * @param size Number of bytes to write.
             * @return True if the write succeeds, false otherwise.
             */
            virtual bool WritePhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) = 0;

            /**
             * @brief Attempts to bypass Driver Signature Enforcement.
             * @return True if DSE bypass succeeds, false otherwise.
             */
            virtual bool BypassDSE() = 0;

            /**
             * @brief Gets the provider's capabilities.
             * @return Combined capability flags.
             */
            virtual ULONG GetCapabilities() const = 0;

            /**
             * @brief Gets the provider's load configuration.
             * @return Pointer to load data structure.
             */
            virtual const ProviderLoadData* GetLoadData() const = 0;

            /**
             * @brief Translates virtual address to physical address.
             * @param virtualAddress The virtual address to translate.
             * @return Physical address, or 0 on failure.
             */
            virtual uintptr_t VirtualToPhysical(uintptr_t virtualAddress) = 0;

            /**
             * @brief Allocates executable kernel memory.
             * @param size Size of memory to allocate.
             * @param physicalAddress Optional output for physical address.
             * @return Virtual address of allocated memory, or 0 on failure.
             */
            virtual uintptr_t AllocateKernelMemory(size_t size, uintptr_t* physicalAddress = nullptr) = 0;

            /**
             * @brief Frees previously allocated kernel memory.
             * @param virtualAddress Virtual address to free.
             * @param size Size of memory block.
             * @return True if memory was freed successfully.
             */
            virtual bool FreeKernelMemory(uintptr_t virtualAddress, size_t size) = 0;

            /**
             * @brief Creates a system thread to execute code in kernel mode.
             * @param startAddress Virtual address of code to execute.
             * @param parameter Optional parameter to pass to thread.
             * @return True if thread was created successfully.
             */
            virtual bool CreateSystemThread(uintptr_t startAddress, uintptr_t parameter = 0) = 0;

            /**
             * @brief Reads a Model Specific Register (MSR).
             * @param msrIndex The MSR index to read.
             * @param value Output for the MSR value.
             * @return True if successful, false otherwise.
             */
            virtual bool ReadMsr(ULONG msrIndex, ULONG64* value) { 
                UNREFERENCED_PARAMETER(msrIndex);
                UNREFERENCED_PARAMETER(value);
                return false; 
            }

            /**
             * @brief Writes a Model Specific Register (MSR).
             * @param msrIndex The MSR index to write.
             * @param value The value to write.
             * @return True if successful, false otherwise.
             */
            virtual bool WriteMsr(ULONG msrIndex, ULONG64 value) {
                UNREFERENCED_PARAMETER(msrIndex);
                UNREFERENCED_PARAMETER(value);
                return false;
            }

            /**
             * @brief Template method for reading typed data.
             */
            template<typename T>
            bool ReadKernelMemory(uintptr_t address, T& value) {
                return ReadKernelMemory(address, &value, sizeof(T));
            }

            /**
             * @brief Template method for writing typed data.
             */
            template<typename T>
            bool WriteKernelMemory(uintptr_t address, const T& value) {
                return WriteKernelMemory(address, const_cast<T*>(&value), sizeof(T));
            }
            
            /**
             * @brief Checks if the provider is in an error state (LIFECYCLE-011 fix).
             * @return True if provider is in error state and cannot be used.
             */
            virtual bool IsInErrorState() const { return false; }  // Default: not in error
            
            /**
             * @brief Checks if the provider is initialized and ready to use.
             * @return True if provider is initialized and operational.
             */
            virtual bool IsInitialized() const { return true; }  // Default: initialized

        protected:
            /**
             * @brief Helper method to extract driver using DriverDataManager.
             * @param driverId The driver ID to extract.
             * @param outputPath Path where driver should be extracted.
             * @return True if extraction succeeds, false otherwise.
             */
            bool ExtractDriverFromResources(ULONG driverId, const std::wstring& outputPath);
        };

    } // namespace Providers
} // namespace KernelMode