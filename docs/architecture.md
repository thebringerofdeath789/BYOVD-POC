# KernelMode / BYOVD-POC Architecture

## 🔍 High-Level Overview

**KernelMode** is an advanced Windows kernel exploitation toolkit based on the **Bring Your Own Vulnerable Driver (BYOVD)** technique. It is architecturally inspired by the [KDU (Kernel Driver Utility)](https://github.com/hfiref0x/KDU) project by hFiref0x.

The core design revolves around a **Provider/Manager** abstraction:
1.  **Manager**: Orchestrates the attack lifecycle (Extraction -> Loading -> Exploitation -> Cleanup).
2.  **Providers**: Modular implementations for specific vulnerable drivers (e.g., RTCore, GDRV, DBUtil).
3.  **Resources**: Securely embedded driver binaries (`.bin` format) that are decrypted and decompressed on demand.

## 🏗️ Core Components

### 1. Provider System (`ProviderSystem.h`)
The `ProviderSystem` defines the interface that all vulnerable driver exploits must implement. This allows the toolkit to switch between different drivers seamlessly without changing the core logic for memory primitives.

**Key Abstractions:**
*   **`DRIVER_PROVIDER`**: Struct containing function pointers for primitives (Read/Write Kernel VM, Physical Memory, DSE Control).
*   **`PROVIDER_CONTEXT`**: Maintains state for a loaded driver (Device Handle, Driver Name, OS Build Info).
*   **Capabilities**: Flags like `PROVIDER_CAP_DSE_BYPASS` or `PROVIDER_CAP_PHYSICAL_MEMORY` define what a specific driver can do.

### 2. BYOVD Manager (`BYOVDManager` class)
The central nervous system of the toolkit. It handles the high-level logic of the attack chain.

*   **File**: `KernelMode/BYOVDManager.cpp`
*   **Initialization**: Scans for compatible drivers based on the current OS version.
*   **Attack Orchestration**:
    *   **`LoadVulnerableDriver`**: Loads the chosen provider (e.g., RTCore64) to gain initial R/W primitives.
    *   **`Exploit` / `DisableDSE`**: Patches `g_CiOptions` to disable signature checks.
    *   **`LoadSilentRK`**: The primary public API. It manages the full chain: Load Provider -> Disable DSE -> Load Payload -> Restore DSE.
*   **Safety**: Validates OS build numbers and HVCI status before attempting exploits.

### 3. Resource & Driver Management (`DriverDataManager`)
Manages the embedded vulnerable drivers which are stored as encrypted/compressed resources to evade static analysis.

*   **Storage**: Drivers are stored as resources in the binary.
*   **Extraction**:
    1.  **Decrypt**: Uses XOR keys (e.g., `0xF62E6CE0`) to decrypt the resource.
    2.  **Decompress**: Uses Microsoft Delta Compression API (`msdelta.dll`) to inflate `.bin` files into valid `.sys` files.
    *   *Note: There is a known issue with the decompression logic producing invalid PE headers (50 EC 9E C1) currently under investigation.*

### 4. Bypass Mechanisms
*   **DSE (Driver Signature Enforcement) Bypass**:
    *   Locates `g_CiOptions` variable in the kernel.
    *   Uses the Read/Write primitive provided by the Vulnerable Driver to patch the value (enable/disable signing).
*   **PPL (Protected Process Light)**:
    *   Removes protection flags from target processes to allow access (e.g., for dumping LSASS or blinding EDR).

## 🔄 Execution Flow

1.  **Startup (`Main.cpp`)**:
    *   Checks for Administrator privileges.
    *   Initializes `DriverDataManager` and `BYOVDManager`.

2.  **Driver Selection**:
    *   User selects a target vulnerable driver (e.g., RTCore64.sys).
    *   `DriverDataManager` extracts the `.sys` file to disk (usually `C:\Windows\Temp`).

3.  **Service Creation (`ServiceManager`)**:
    *   Registers a legacy kernel driver service for the extracted file.
    *   Starts the service to load the driver into the kernel.

4.  **Exploitation Loop**:
    *   Opens a handle to the driver's device object.
    *   Sends IOCTLs to trigger the vulnerability.
    *   Establishes R/W primitives.
    *   Performs the desired action (Token Stealing, DSE Patching, etc.).

5.  **Cleanup**:
    *   Stops the service.
    *   Unloads the driver.
    *   Deletes the `.sys` file from disk to minimize forensic footprint.

## 📂 Project Structure

*   `KernelMode/`: Core C++ source files.
    *   `Providers/`: Specific driver implementations.
    *   `Resources/`: Encrypted driver binaries.
*   `tests/`: Comprehensive test suite for debugging extraction and primitives.
*   `docs/`: Documentation.
*   `archive/`: Deprecated or temporary files.

## ⚠️ Key Technical Challenges
*   **Delta Compression**: The project uses the native Windows Delta Compression API, which is complex and undocumented, leading to the current `.bin` extraction bugs.
*   **Pattern Scanning**: Locating kernel variables `g_CiOptions` requires robust pattern scanning that must survie OS updates.
