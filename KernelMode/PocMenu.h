/**
 * @file PocMenu.h
 * @author Gregory King
 * @date August 13, 2025
 * @brief This file contains the declaration of the PocMenu class.
 *
 * The PocMenu class manages the console interface for the kernel toolkit,
 * including provider selection, action execution, and utility access. Updated
 * to support KDU-style driver management.
 */

#pragma once

#include "DSE.h"
#include "ManualMapper.h"
#include "Providers/IProvider.h"
#include "ProviderSystem.h"
#include "ServiceManager.h"
#include <fstream>

// Global log file declaration
extern std::ofstream g_logFile;

// Logging helper macro - outputs to both console and log file
#define LOG_OUTPUT(msg) do { \
    std::cout << msg; \
    if (g_logFile.is_open()) { \
        g_logFile << msg; \
        g_logFile.flush(); \
    } \
} while(0)
#include "Resources/DriverDataManager.h"
#include "Victim.h"
#include <memory> 

namespace KernelMode {
    /**
     * @class PocMenu
     * @brief Manages the console user interface for the toolkit.
     *
     * This class provides a menu-driven interface for users to select
     * providers, execute various kernel-level operations, and access utilities.
     * Updated to support KDU-style driver management with automatic driver selection.
     */
    class PocMenu {
    public:
        PocMenu();
        ~PocMenu();

        /**
         * @brief Starts the main menu loop.
         */
        void Run();

    private:
        /**
         * @brief Displays the application banner.
         */
        void DisplayBanner();

        /**
         * @brief Gets user input and validates the choice.
         * @param maxChoice The maximum valid choice.
         * @return The user's choice, or -1 if invalid.
         */
        int GetUserChoice(int maxChoice);

        /**
         * @brief Handles provider selection with KDU-style driver management.
         */
        void SelectProvider();

        /**
         * @brief Displays and handles the provider actions menu.
         */
        void ProviderActionsMenu();

        /**
         * @brief Handles DSE bypass operations.
         */
        void HandleDseBypass();

        /**
         * @brief Handles manual driver mapping operations.
         */
        void HandleManualMap();

        /**
         * @brief Handles PE parser utility.
         */
        void HandlePeParser();

        /**
         * @brief Auto-loads the SilentRK driver using BYOVD techniques.
         */
        void HandleAutoLoadSilentRK();

        /**
         * @brief Handles loading a victim driver for safe execution.
         */
        void HandleLoadVictim();

        /**
         * @brief Attempts to find and use system-installed vulnerable drivers.
         * @return True if a compatible driver is found and loaded, false otherwise.
         */
        bool FindSystemVulnerableDrivers();

        /**
         * @brief Attempts direct DSE bypass using memory techniques.
         * @return True if DSE bypass successful, false otherwise.
         */
        bool AttemptDirectDSEBypass();

        /**
         * @brief Attempts service-based driver loading.
         * @param driverPath Path to the driver to load.
         * @return True if loading successful, false otherwise.
         */
        bool AttemptServiceBasedLoading(const std::wstring& driverPath);

        /**
         * @brief Attempts physical memory injection of driver.
         * @param driverPath Path to the driver to inject.
         * @return True if injection successful, false otherwise.
         */
        bool AttemptPhysicalMemoryInjection(const std::wstring& driverPath);

        /**
         * @brief Attempts KDU-style physical memory mapping technique.
         * @return True if successful, false otherwise.
         */
        bool AttemptPhysicalMemoryMapping();

        /**
         * @brief Attempts KDU-style virtual memory mapping technique.
         * @return True if successful, false otherwise.
         */
        bool AttemptVirtualMemoryMapping();

        /**
         * @brief Executes shellcode using specified technique (V1-V4).
         * @param shellcodeVersion Version of KDU shellcode to use (1-4).
         * @return True if shellcode execution successful, false otherwise.
         */
        bool ExecuteKDUShellcode(int shellcodeVersion);

        /**
         * @brief Attempts provider-based driver mapping using loaded vulnerable driver.
         * @param driverPath Path to the driver to map.
         * @param context Provider context with loaded vulnerable driver.
         * @return True if mapping successful, false otherwise.
         */
        bool AttemptProviderBasedMapping(const std::wstring& driverPath, PPROVIDER_CONTEXT context);

        /**
         * @brief Applies stealth techniques using provider capabilities.
         * @param context Provider context with active provider.
         */
        void ApplyStealthTechniques(PPROVIDER_CONTEXT context);

        /**
         * @brief Extracts and loads a vulnerable driver using KDU-style extraction.
         * @return True if extraction and loading successful, false otherwise.
         */
        bool ExtractAndLoadVulnerableDriver();

        /**
         * @brief Extracts a .bin file to a .sys file (signed driver extraction).
         * @param binPath Path to the .bin file containing the signed driver.
         * @param sysPath Path where the .sys file should be created.
         * @return True if extraction successful, false otherwise.
         */
        bool ExtractBinToSys(const std::wstring& binPath, const std::wstring& sysPath);

        /**
         * @brief Loads a signed driver via Windows service manager.
         * @param sysPath Path to the extracted .sys driver file.
         * @param serviceName Name of the service to create for the driver.
         * @return True if driver loaded successfully, false otherwise.
         */
        bool LoadSignedDriver(const std::wstring& sysPath, const std::wstring& serviceName);

        // Core components
        std::unique_ptr<ServiceManager> serviceManager;
        std::shared_ptr<Providers::IProvider> activeProvider;
        std::unique_ptr<DSE> dseManager;
        std::unique_ptr<ManualMapper> manualMapper;
        std::shared_ptr<Victim> victim;
    };
}