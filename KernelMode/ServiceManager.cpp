/**
 * @file ServiceManager.cpp
 * @author Gregory King
 * @date September 9, 2025
 * @brief Implementation of centralized service management
 */

#include "ServiceManager.h"
#include <iostream>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <chrono>
#include <thread>

namespace KernelMode {

// Helper class for RAII SC_HANDLE management
class ScopedScHandle {
    SC_HANDLE handle;
public:
    ScopedScHandle(SC_HANDLE h) : handle(h) {}
    ~ScopedScHandle() { if (handle) CloseServiceHandle(handle); }
    operator SC_HANDLE() const { return handle; }
    SC_HANDLE get() const { return handle; }
    bool isValid() const { return handle != NULL; }
    // Disable copying
    ScopedScHandle(const ScopedScHandle&) = delete;
    ScopedScHandle& operator=(const ScopedScHandle&) = delete;
};

ServiceManager::ServiceManager(const std::wstring& baseServiceName) 
    : baseServiceName(baseServiceName), instanceCounter(0) {
    std::wcout << L"[*] ServiceManager initialized for: " << baseServiceName << std::endl;
}

ServiceManager::~ServiceManager() {
    CleanupAllServices();
}

ServiceStatus ServiceManager::GetInternalServiceStatus(const std::wstring& serviceName) {
    ScopedScHandle scmHandle(OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT));
    if (!scmHandle.isValid()) {
        return ServiceStatus::UNKNOWN;
    }

    ScopedScHandle serviceHandle(OpenServiceW(scmHandle.get(), serviceName.c_str(), SERVICE_QUERY_STATUS));
    if (!serviceHandle.isValid()) {
        return ServiceStatus::NOT_FOUND;
    }

    SERVICE_STATUS status;
    ServiceStatus result = ServiceStatus::UNKNOWN;
    
    if (::QueryServiceStatus(serviceHandle.get(), &status)) {
        switch (status.dwCurrentState) {
            case SERVICE_STOPPED:
                result = ServiceStatus::STOPPED;
                break;
            case SERVICE_RUNNING:
                result = ServiceStatus::RUNNING;
                break;
            case SERVICE_START_PENDING:
                result = ServiceStatus::STARTING;
                break;
            case SERVICE_STOP_PENDING:
                result = ServiceStatus::STOPPING;
                break;
            case SERVICE_PAUSED:
                result = ServiceStatus::PAUSED;
                break;
            default:
                result = ServiceStatus::ERROR_STATE;
                break;
        }
    }

    return result;
}

bool ServiceManager::IsServiceOurs(const std::wstring& serviceName) {
    for (const auto& service : managedServices) {
        if (service.serviceName == serviceName) {
            return true;
        }
    }
    return false;
}

std::wstring ServiceManager::GenerateUniqueServiceName(const std::wstring& baseName) {
    std::wstring uniqueName;
    int safetyCounter = 0;
    const int MAX_ATTEMPTS = 100;

    do {
        std::wstringstream ss;
        ss << baseName;
        if (instanceCounter > 0) {
            ss << L"_" << instanceCounter;
        }
        uniqueName = ss.str();
        instanceCounter++;
        safetyCounter++;

        ServiceStatus status = GetInternalServiceStatus(uniqueName);
        if (status == ServiceStatus::UNKNOWN) {
             // BUG-009 FIX: Fail hard if SCM is unreachable
             std::wcerr << L"[-] SCM unreachable during name generation." << std::endl;
             return L"";
        }
        if (status == ServiceStatus::NOT_FOUND) {
            break;
        }

    } while (safetyCounter < MAX_ATTEMPTS);
    
    if (safetyCounter >= MAX_ATTEMPTS) {
        return L""; // Failed to find unique name
    }
    
    return uniqueName;
}

ServiceInfo ServiceManager::CheckServiceStatus(const std::wstring& serviceName) {
    ServiceInfo info;
    info.serviceName = serviceName;
    info.status = GetInternalServiceStatus(serviceName);
    info.isOurService = IsServiceOurs(serviceName);
    info.processId = 0;

    if (info.status != ServiceStatus::NOT_FOUND) {
        ScopedScHandle scmHandle(OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT));
        if (scmHandle.isValid()) {
            ScopedScHandle serviceHandle(OpenServiceW(scmHandle.get(), serviceName.c_str(), SERVICE_QUERY_CONFIG));
            if (serviceHandle.isValid()) {
                // Get service config to determine driver path
                DWORD bytesNeeded = 0;
                QueryServiceConfigW(serviceHandle.get(), NULL, 0, &bytesNeeded);
                
                if (bytesNeeded > 0) {
                    std::vector<BYTE> buffer(bytesNeeded);
                    LPQUERY_SERVICE_CONFIGW config = (LPQUERY_SERVICE_CONFIGW)buffer.data();
                    
                    if (QueryServiceConfigW(serviceHandle.get(), config, bytesNeeded, &bytesNeeded)) {
                        if (config->lpBinaryPathName) {
                            info.driverPath = config->lpBinaryPathName;
                        }
                        if (config->lpDisplayName) {
                            info.displayName = config->lpDisplayName;
                        }
                    }
                }
            }
        }
    }

    return info;
}

ServiceInfo ServiceManager::InstallDriverService(
    const std::wstring& preferredName,
    const std::wstring& driverPath,
    const std::wstring& displayName,
    DWORD serviceType) {
    
    ServiceInfo result;
    result.serviceName = preferredName;
    result.driverPath = driverPath;
    result.displayName = displayName;
    result.status = ServiceStatus::ERROR_STATE;
    result.isOurService = false;

    ScopedScHandle scmHandle(OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS));
    if (!scmHandle.isValid()) {
        std::wcerr << L"[-] Failed to open SCM: " << GetLastError() << std::endl;
        return result;
    }

    // --- BUG-006 FIX: TOCTOU Removal ---
    // Removed pre-check (GetInternalServiceStatus) to avoid race conditions.
    // relying on CreateServiceW to handle collisions atomically.
    // -----------------------------------

    // Handle paths with spaces by quoting them ONLY if not a kernel driver (drivers take path literally)
    std::wstring finalPath = driverPath;
    if (serviceType != SERVICE_KERNEL_DRIVER && serviceType != SERVICE_FILE_SYSTEM_DRIVER) {
        if (finalPath.find(L' ') != std::wstring::npos && finalPath.front() != L'\"') {
            finalPath = L"\"" + finalPath + L"\"";
        }
    }

    // Create the service
    ScopedScHandle serviceHandle(CreateServiceW(
        scmHandle.get(),
        preferredName.c_str(),
        displayName.c_str(),
        SERVICE_ALL_ACCESS,
        serviceType,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        finalPath.c_str(),
        NULL, NULL, NULL, NULL, NULL
    ));

    if (!serviceHandle.isValid()) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_EXISTS) {
             // BUG-006 FIX: Handle existing service gracefully and UPDATE path
             std::wcout << L"[!] Service '" << preferredName << L"' already exists. Updating configuration." << std::endl;
             
             ScopedScHandle existingService(OpenServiceW(scmHandle.get(), preferredName.c_str(), SERVICE_ALL_ACCESS));
             if (existingService.isValid()) {
                // Check if running and stop if needed
                SERVICE_STATUS status = { 0 };
                if (QueryServiceStatus(existingService.get(), &status) && status.dwCurrentState != SERVICE_STOPPED) {
                     ControlService(existingService.get(), SERVICE_CONTROL_STOP, &status);
                     Sleep(500);
                }

                if (!ChangeServiceConfigW(
                    existingService.get(),
                    SERVICE_NO_CHANGE,
                    SERVICE_NO_CHANGE,
                    SERVICE_NO_CHANGE,
                    finalPath.c_str(), 
                    NULL, NULL, NULL, NULL, NULL, NULL)) {
                        std::wcerr << L"[!] Warning: Failed to update existing service path: " << GetLastError() << std::endl;
                } else {
                        std::wcout << L"[+] Existing service path updated to: " << finalPath << std::endl;
                }
             }

             // Do NOT treat as fatal error, just update status
             result.status = GetInternalServiceStatus(preferredName);
             return result;
        }

        std::wcerr << L"[-] Failed to create service '" << preferredName << L"': " << error << std::endl;
        return result;
    }

    std::wcout << L"[+] Service '" << preferredName << L"' created successfully" << std::endl;

    result.status = ServiceStatus::STOPPED;
    result.isOurService = true;
    managedServices.push_back(result);

    return result;
}

bool ServiceManager::StartDriverService(const std::wstring& serviceName) {
    ScopedScHandle scmHandle(OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT));
    if (!scmHandle.isValid()) {
        std::wcerr << L"[-] Failed to open SCM for starting service" << std::endl;
        return false;
    }

    ScopedScHandle serviceHandle(OpenServiceW(scmHandle.get(), serviceName.c_str(), SERVICE_ALL_ACCESS));
    if (!serviceHandle.isValid()) {
        std::wcerr << L"[-] Failed to open service '" << serviceName << L"' for starting" << std::endl;
        return false;
    }
    
    // Debug: Check config
    DWORD needed = 0;
    QueryServiceConfigW(serviceHandle.get(), NULL, 0, &needed);
    if (needed > 0) {
        std::vector<BYTE> buffer(needed);
        LPQUERY_SERVICE_CONFIGW config = (LPQUERY_SERVICE_CONFIGW)buffer.data();
        if (QueryServiceConfigW(serviceHandle.get(), config, needed, &needed)) {
            if (config->lpBinaryPathName) {
                std::wcout << L"[*] Service Binary Path: " << config->lpBinaryPathName << std::endl;
                std::ofstream log("c:\\Users\\admin\\Documents\\Visual Studio 2022\\Projects\\BYOVD-POC\\service_debug.txt", std::ios::app);
                if (log.is_open()) {
                     std::wstring ws(config->lpBinaryPathName);
                     std::string s(ws.begin(), ws.end());
                     log << "[*] Service Binary Path: " << s << std::endl;
                }
            } else {
                 std::wcout << L"[*] Service Binary Path: (NULL)" << std::endl;
            }
        }
    }

    // LIFECYCLE-007 FIX: Allow restart after Stop()
    // Removed "already started" check to enable Start() → Stop() → Start() cycle
    
    bool success = false;
    if (::StartServiceW(serviceHandle.get(), 0, NULL)) {
        std::wcout << L"[+] Service '" << serviceName << L"' started successfully" << std::endl;
        std::ofstream log("c:\\Users\\admin\\Documents\\Visual Studio 2022\\Projects\\BYOVD-POC\\service_debug.txt", std::ios::app);
        if(log.is_open()) log << "[+] Service started successfully" << std::endl;
        success = true;
    } else {
        DWORD error = GetLastError();
        std::ofstream log("c:\\Users\\admin\\Documents\\Visual Studio 2022\\Projects\\BYOVD-POC\\service_debug.txt", std::ios::app);
        if(log.is_open()) log << "[-] Failed to start service: " << error << std::endl;

        if (error == ERROR_SERVICE_ALREADY_RUNNING) {
            std::wcout << L"[*] Service '" << serviceName << L"' is already running" << std::endl;
            success = true;
        } else {
            std::wcerr << L"[-] Failed to start service '" << serviceName << L"': " << error << std::endl;
        }
    }

    return success;
}

bool ServiceManager::StopService(const std::wstring& serviceName) {
    // Only stop services we created
    if (!IsServiceOurs(serviceName)) {
        std::wcout << L"[!] Refusing to stop service '" << serviceName 
                   << L"' - not created by our tool" << std::endl;
        return false;
    }

    return StopAndDeleteService(serviceName);
}

bool ServiceManager::StopAndDeleteService(const std::wstring& serviceName) {
    ScopedScHandle scmHandle(OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS));
    if (!scmHandle.isValid()) {
        return false;
    }

    ScopedScHandle serviceHandle(OpenServiceW(scmHandle.get(), serviceName.c_str(), SERVICE_ALL_ACCESS));
    if (!serviceHandle.isValid()) {
        return false;
    }

    // Stop the service
    SERVICE_STATUS serviceStatus;
    if (ControlService(serviceHandle.get(), SERVICE_CONTROL_STOP, &serviceStatus)) {
        std::wcout << L"[*] Stopping service '" << serviceName << L"'..." << std::endl;
        
        // Wait for service to stop
        if (WaitForServiceState(serviceName, SERVICE_STOPPED, 5000)) {
            std::wcout << L"[+] Service '" << serviceName << L"' stopped" << std::endl;
        }
    }

    // Delete the service
    bool success = false;
    if (DeleteService(serviceHandle.get())) {
        std::wcout << L"[+] Service '" << serviceName << L"' deleted" << std::endl;
        success = true;
    } else {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_MARKED_FOR_DELETE) {
            std::wcout << L"[*] Service '" << serviceName << L"' marked for deletion" << std::endl;
            success = true;
        } else {
            std::wcerr << L"[-] Failed to delete service '" << serviceName << L"': " << error << std::endl;
        }
    }

    return success;
}

bool ServiceManager::WaitForServiceState(const std::wstring& serviceName, DWORD targetState, DWORD timeoutMs) {
    auto startTime = std::chrono::steady_clock::now();
    
    while (true) {
        ServiceStatus status = GetInternalServiceStatus(serviceName);
        
        if ((targetState == SERVICE_STOPPED && status == ServiceStatus::STOPPED) ||
            (targetState == SERVICE_RUNNING && status == ServiceStatus::RUNNING)) {
            return true;
        }

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime);
        
        if (elapsed.count() >= timeoutMs) {
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    return false;
}

bool ServiceManager::RemoveService(const std::wstring& serviceName) {
    return StopService(serviceName);
}

bool ServiceManager::CleanupAllServices() {
    std::wcout << L"[*] Cleaning up " << managedServices.size() << L" managed services..." << std::endl;
    
    bool allSuccess = true;
    for (auto it = managedServices.begin(); it != managedServices.end(); ) {
        if (StopAndDeleteService(it->serviceName)) {
            it = managedServices.erase(it);
        } else {
            std::wcerr << L"[-] Failed to cleanup service: " << it->serviceName << std::endl;
            allSuccess = false;
            ++it;
        }
    }

    if (allSuccess && managedServices.empty()) {
        std::wcout << L"[+] All services cleaned up successfully" << std::endl;
    }

    return allSuccess;
}

std::vector<ServiceInfo> ServiceManager::GetManagedServices() const {
    return managedServices;
}

ServiceInfo ServiceManager::FindRunningDriverInstance(const std::wstring& driverFileName) {
    ServiceInfo result;
    result.status = ServiceStatus::NOT_FOUND;

    // This would require enumerating all services and checking their binary paths
    // For now, we'll check common service names that might be related
    std::vector<std::wstring> commonNames = {
        driverFileName.substr(0, driverFileName.find(L'.')),  // Without extension
        baseServiceName,
        baseServiceName + L"_Service"
    };

    for (const auto& name : commonNames) {
        ServiceInfo info = CheckServiceStatus(name);
        if (info.status == ServiceStatus::RUNNING) {
            // Check if it's using the same driver file name
            std::wstring fileName = info.driverPath.substr(info.driverPath.find_last_of(L'\\') + 1);
            if (_wcsicmp(fileName.c_str(), driverFileName.c_str()) == 0) {
                return info;
            }
        }
    }

    return result;
}

ServiceInfo ServiceManager::InstallWithConflictResolution(
    const std::wstring& baseName,
    const std::wstring& driverPath,
    const std::wstring& displayName) {
    
    std::wcout << L"[*] Installing service with conflict resolution..." << std::endl;

    // First, check if there's an existing compatible service
    std::wstring driverFileName = driverPath.substr(driverPath.find_last_of(L'\\') + 1);
    ServiceInfo existing = FindRunningDriverInstance(driverFileName);
    
    if (existing.status == ServiceStatus::RUNNING && !existing.isOurService) {
        std::wcout << L"[!] Found existing running instance: " << existing.serviceName 
                   << L" (not created by our tool)" << std::endl;
        std::wcout << L"[*] Will create new service with different name..." << std::endl;
    }

    // Generate unique service name
    std::wstring uniqueName = GenerateUniqueServiceName(baseName);
    std::wcout << L"[*] Using service name: " << uniqueName << std::endl;

    return InstallDriverService(uniqueName, driverPath, displayName);
}

ServiceInfo ServiceManager::TryUseExistingService(
    const std::wstring& driverFileName,
    const std::wstring& driverPath) {
    
    ServiceInfo existing = FindRunningDriverInstance(driverFileName);
    
    if (existing.status == ServiceStatus::RUNNING) {
        std::wcout << L"[*] Found existing running service: " << existing.serviceName << std::endl;
        
        // If it's our service, we can use it
        if (existing.isOurService) {
            std::wcout << L"[+] Reusing our existing service" << std::endl;
            return existing;
        } else {
            // If it's not ours, verify it's compatible
            // For now, we'll be conservative and not use external services
            std::wcout << L"[!] External service found - will create our own" << std::endl;
        }
    }

    ServiceInfo empty;
    empty.status = ServiceStatus::NOT_FOUND;
    return empty;
}

} // namespace KernelMode
