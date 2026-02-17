# Technical Implementation & Workflows

This document details the internal workflows of the KernelMode toolkit. It describes the step-by-step memory operations and logic used to achieve unsigned driver loading via Bring Your Own Vulnerable Driver (BYOVD).

## 1. The Provider Architecture

The toolkit abstracts specific driver vulnerabilities into a universal interface (`IProvider` / `DRIVER_PROVIDER`). This allows the main logic to remain agnostic of the specific vulnerability being exploited.

### Provider Interface Capabilities
Each provider must implement the following primitives:
*   `ReadKernelVM`: Reading kernel virtual memory (arbitrary).
*   `WriteKernelVM`: Writing kernel virtual memory (arbitrary).
*   `GetPhysicalAddress` (Optional): Translating Virtual -> Physical.

### Supported Providers
*   **RTCore64 (MSI Afterburner)**:
    *   **Device**: `\Device\RTCore64`
    *   **Vulnerability**: Exposed IOCTLs `0x80002000` (Read) and `0x80002004` (Write) allow direct physical memory access.
    *   **Technique**: Maps physical memory to user space or modifies page table entries.
*   **GDRV (Gigabyte)**:
    *   **Device**: `\Device\GIO`
    *   **Vulnerability**: `memcpy`-like primitives exposed via IOCTLs.
*   **DBUtil (Dell)**:
    *   **Device**: `\Device\DBUtil_2_3`
    *   **Vulnerability**: Arbitrary R/W.

---

## 2. Vulnerable Driver Lifecycle

The `DriverDataManager` and `ServiceManager` classes handle the safe deployment of the vulnerable driver.

### Step 1: Extraction
1.  **Resource Lookup**: The toolkit holds encrypted versions of the vulnerable drivers in its resource section (`Resources/`).
2.  **Decryption**: Resources are decrypted using a static XOR key (default KDU key: `0xF62E6CE0`).
3.  **Decompression**:
    *   *Implementation*: The raw data is compressed using Microsoft's Delta Compression (`msdelta.dll`).
    *   *Workflow*:
        1.  `CreateDecompressor` (COMPRESSION_ENGINE_MSDELTA).
        2.  `Decompress` buffer -> Temporary memory.
    *   *Known Issue*: Investigating invalid PE header output (50 EC 9E C1) during this stage.

### Step 2: Service Registration
1.  **File Placement**: The decrypted `.sys` file is written to `%TEMP%\<RandomName>.sys`.
2.  **SCM Interaction**:
    *   `OpenSCManager` (SC_MANAGER_CREATE_SERVICE).
    *   `CreateService` (KERNEL_DRIVER type).
    *   **Important**: The tool generates a unique, random service name to avoid detection and collision.

### Step 3: Kernel Loading
1.  `StartService`: Triggers `NtLoadDriver`.
2.  **Verification**: The toolkit waits for the service status to become `SERVICE_RUNNING`.

### Step 4: Device Initialization
1.  `CreateFile`: Opens a handle to the driver's device object (e.g., `\\.\RTCore64`).
2.  If successful, the handle is stored in the `PROVIDER_CONTEXT` for future IOCTLs.

---

## 3. DSE Bypass Workflow

Driver Signature Enforcement (DSE) is disabled by modifying the `g_CiOptions` global variable in the kernel.

### Stage 1: Locating `g_CiOptions`
Since `g_CiOptions` is not exported, we must find it dynamically:

1.  **Base Address**: Retrieve the kernel base address (`NtOsBase`) using `EnumDeviceDrivers`.
2.  **User-Mode Analysis**:
    *   Load `ci.dll` (Code Integrity library) into the *user-mode* process memory using `LoadLibraryEx(DONT_RESOLVE_DLL_REFERENCES)`.
    *   This allows us to scan the code without triggering kernel protections.
3.  **Pattern Scanning**:
    *   Search `ci.dll` for the instruction pattern that references variable: `48 8D 0D ...` (LEA RCX, [RIP + offset]).
    *   This pattern is typically found inside `CiInitialize`.
4.  **Offset Calculation**:
    *   `TargetAddress = PatternAddress + RIP_Offset + InstructionLength`.
    *   `Delta = TargetAddress - UserMode_CiDll_Base`.
    *   `Kernel_CiOptions_Address = Kernel_CiDll_Base + Delta`.

### Stage 2: Patching
1.  **Backup**: Read the current value of `g_CiOptions` using the Vulnerable Driver Primitive and store it (`OriginalCiOptions`).
2.  **Disable**: Write `0x00000000` (or `0x0000000E` depending on version) to the address.
    *   *Effect*: Windows now allows loading unsigned drivers.

---

## 4. Unsigned Driver Loading (The Payload)

The `BYOVDManager` class orchestrates the loading of unsigned drivers (e.g., `SilentRK.sys`) using two distinct methods.

### Method A: DSE Disable + Service Load (Preferred)
This method is the most stable as it uses the OS's native image loader handling.

1.  **Orchestration**: `BYOVDManager::LoadSilentRK(..., BYOVDMethod::DSEDisable)`
2.  **DSE Bypass**: The manager uses the active provider (e.g., RTCore64) to patch `g_CiOptions` to `0`.
3.  **Service Creation**:
    *   Uses `ServiceManager` to create a standard kernel service for `SilentRK.sys`.
    *   Calls `StartService`.
4.  **Verification**: Checks if the driver module appears in the loaded module list.
5.  **Restoration**: Immediately restores DSE to its original value to minimize detection risk.

### Method B: Manual Mapping (Stealth)
This method avoids creating a service entry but requires complex PE parsing and memory management.

1.  **Orchestration**: `BYOVDManager::LoadSilentRK(..., BYOVDMethod::ManualMapping)`
2.  **Allocation**:
    *   `ManualMapper` parses the target `.sys` file headers to determine `SizeOfImage`.
    *   Allocates executable kernel memory via the Provider (`AllocateKernelMemory`).
        *   *Note*: Some providers (e.g., RTCore) require finding existing executable holes or using specific pools.
3.  **Mapping**:
    *   **Sections**: Copies PE sections (text, data, rdata) to the allocated kernel memory.
    *   **Relocations**: Processes the `.reloc` section to adjust pointers for the new base address.
    *   **Imports**: Resolves kernel API imports (`ntoskrnl.exe`, `wdf01000.sys`, etc.) by walking the Export Address Table of loaded modules.
4.  **Execution**:
    *   Creates a system thread or uses a hook (e.g., `qword` patch) to redirect execution to the driver's `DriverEntry`.
    *   Shellcode trampoline is often used to prepare the definition of `DRIVER_OBJECT`.

---

## 5. Cleanup Phase

To maintain stealth and system stability:

1.  **Close Handles**: Close device handles to `RTCore64` etc.
2.  **Stop Service**: `ControlService(SERVICE_CONTROL_STOP)`.
3.  **Delete Service**: `DeleteService`.
4.  **File Removal**: Delete the `%TEMP%` driver file.
