/**
 * @file ProviderManager.h
 * @author Gregory King  
 * @date September 7, 2025
 * @brief KDU-style provider management system for auto-loading vulnerable drivers.
 */

#pragma once

#include "IProvider.h"
#include "RTCoreProvider.h"
#include "GdrvProvider.h" 
#include "DBUtilProvider.h"
#include "IntelNalProvider.h"
#include <memory>
#include <vector>
#include <string>
#include <functional>

namespace KernelMode {
    namespace Providers {

        /**
         * @enum ProviderType
         * @brief Enumeration of available provider types.
         */
        enum ProviderType {
            PROVIDER_RTCORE64 = 0,
            PROVIDER_GDRV = 1,
            PROVIDER_DBUTIL = 2,
            PROVIDER_INTEL_NAL = 3,
            PROVIDER_AUTO = 999    // Auto-select best provider
        };

        /**
         * @struct ProviderInfo
         * @brief Information about a provider in the KDU-style database.
         */
        struct ProviderInfo {
            ProviderType Type;
            const wchar_t* Name;
            const wchar_t* Description;
            ULONG Capabilities;
            bool RequiresDSE;
            std::function<std::unique_ptr<IProvider>()> CreateProvider;
        };

        /**
         * @class ProviderManager
         * @brief KDU-style provider management system for auto-loading and testing multiple providers.
         */
        class ProviderManager {
        public:
            ProviderManager();
            ~ProviderManager();

            /**
             * @brief Attempts to auto-load any available provider.
             * @param bypassDSE Whether to attempt DSE bypass.
             * @return Pointer to successfully loaded provider, or nullptr on failure.
             */
            std::unique_ptr<IProvider> AutoLoadProvider(bool bypassDSE = true);

            /**
             * @brief Loads a specific provider by type.
             * @param providerType The provider type to load.
             * @param bypassDSE Whether to attempt DSE bypass.
             * @return Pointer to loaded provider, or nullptr on failure.
             */
            std::unique_ptr<IProvider> LoadProvider(ProviderType providerType, bool bypassDSE = true);

            /**
             * @brief Gets information about all available providers.
             * @return Vector of provider information structures.
             */
            const std::vector<ProviderInfo>& GetAvailableProviders() const;

            /**
             * @brief Tests if a provider can successfully read/write kernel memory.
             * @param provider The provider to test.
             * @return True if provider passes basic functionality tests.
             */
            bool TestProvider(IProvider* provider);

            /**
             * @brief Performs advanced loading with automatic provider selection and DSE bypass.
             * @return Pointer to best working provider, or nullptr if all fail.
             */
            std::unique_ptr<IProvider> AdvancedAutoLoad();

            /**
             * @brief Gets the number of available providers.
             * @return Number of providers in the database.
             */
            size_t GetProviderCount() const;

        private:
            std::vector<ProviderInfo> providerDatabase;

            /**
             * @brief Initializes the provider database.
             */
            void InitializeProviderDatabase();

            /**
             * @brief Attempts to perform global DSE bypass before loading providers.
             * @return True if DSE bypass succeeds or is not needed.
             */
            bool AttemptGlobalDSEBypass();

            /**
             * @brief Tests basic memory operations on a provider.
             * @param provider The provider to test.
             * @return True if basic tests pass.
             */
            bool RunBasicTests(IProvider* provider);

            /**
             * @brief Tests advanced memory operations on a provider.
             * @param provider The provider to test.
             * @return True if advanced tests pass.
             */
            bool RunAdvancedTests(IProvider* provider);
        };

    } // namespace Providers
} // namespace KernelMode
