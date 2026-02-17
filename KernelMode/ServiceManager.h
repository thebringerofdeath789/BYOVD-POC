/**
 * @file ServiceManager.h
 * @author Gregory King
 * @date September 9, 2025
 * @brief Centralized service management for vulnerable drivers
 * 
 * This class handles all service lifecycle operations including:
 * - Checking existing service status
 * - Installing services with conflict resolution
 * - Proper cleanup on failure
 * - Managing service names to avoid conflicts
 */

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <memory>

namespace KernelMode {
    
    /**
     * @enum ServiceStatus
     * @brief Comprehensive service status information
     */
    enum class ServiceStatus {
        NOT_FOUND,              // Service doesn't exist
        STOPPED,                // Service exists but is stopped
        RUNNING,                // Service is active and running
        STOPPING,               // Service is in process of stopping
        STARTING,               // Service is in process of starting
        PAUSED,                 // Service is paused
        ERROR_STATE,            // Service is in error state
        UNKNOWN                 // Unable to determine status
    };

    /**
     * @struct ServiceInfo
     * @brief Information about a service instance
     */
    struct ServiceInfo {
        std::wstring serviceName;
        std::wstring displayName;
        std::wstring driverPath;
        ServiceStatus status;
        bool isOurService;              // True if created by our tool
        DWORD processId;                // For running services
        std::wstring description;
    };

    /**
     * @class ServiceManager
     * @brief Centralized service management for vulnerable drivers
     */
    class ServiceManager {
    private:
        std::vector<ServiceInfo> managedServices;    // Services we've created
        std::wstring baseServiceName;                // Base name for our services
        DWORD instanceCounter;                       // Counter for unique naming

        // Internal helpers
        ServiceStatus GetInternalServiceStatus(const std::wstring& serviceName);
        bool IsServiceOurs(const std::wstring& serviceName);
        std::wstring GenerateUniqueServiceName(const std::wstring& baseName);
        bool WaitForServiceState(const std::wstring& serviceName, DWORD targetState, DWORD timeoutMs = 10000);

    public:
        ServiceManager(const std::wstring& baseServiceName = L"ByovdPocService");
        ~ServiceManager();

        bool StopAndDeleteService(const std::wstring& serviceName);

        /**
         * @brief Check if a service with the given name exists and its status
         * @param serviceName The service name to check
         * @return ServiceInfo containing status and details
         */
        ServiceInfo CheckServiceStatus(const std::wstring& serviceName);

        /**
         * @brief Install a driver service with conflict resolution
         * @param preferredName Preferred service name
         * @param driverPath Full path to driver file
         * @param displayName Display name for the service
         * @param serviceType Service type (default: SERVICE_KERNEL_DRIVER)
         * @return ServiceInfo for the created service, or empty on failure
         */
        ServiceInfo InstallDriverService(
            const std::wstring& preferredName,
            const std::wstring& driverPath,
            const std::wstring& displayName,
            DWORD serviceType = SERVICE_KERNEL_DRIVER
        );

        /**
         * @brief Start a service by name
         * @param serviceName The service to start
         * @return True if service started successfully
         */
        bool StartDriverService(const std::wstring& serviceName);

        /**
         * @brief Stop a service by name (only if it's ours)
         * @param serviceName The service to stop
         * @return True if service stopped successfully
         */
        bool StopService(const std::wstring& serviceName);

        /**
         * @brief Remove a service (only if it's ours)
         * @param serviceName The service to remove
         * @return True if service removed successfully
         */
        bool RemoveService(const std::wstring& serviceName);

        /**
         * @brief Clean up all services created by this manager
         * @return True if all services cleaned up successfully
         */
        bool CleanupAllServices();

        /**
         * @brief Get list of all services we've created
         * @return Vector of ServiceInfo for managed services
         */
        std::vector<ServiceInfo> GetManagedServices() const;

        /**
         * @brief Check if any instance of a driver is running (by driver file name)
         * @param driverFileName The driver file name to check for
         * @return ServiceInfo of running instance, or empty if none found
         */
        ServiceInfo FindRunningDriverInstance(const std::wstring& driverFileName);

        /**
         * @brief Install service with automatic conflict resolution
         * This will check for existing instances and create a unique name if needed
         * @param baseName Base name for the service
         * @param driverPath Path to driver file
         * @param displayName Display name
         * @return ServiceInfo for created service
         */
        ServiceInfo InstallWithConflictResolution(
            const std::wstring& baseName,
            const std::wstring& driverPath,
            const std::wstring& displayName
        );

        /**
         * @brief Attempt to use existing compatible service
         * @param driverFileName Driver file name to look for
         * @param driverPath Our driver path (for comparison)
         * @return ServiceInfo if compatible service found and usable
         */
        ServiceInfo TryUseExistingService(
            const std::wstring& driverFileName,
            const std::wstring& driverPath
        );
    };

} // namespace KernelMode
