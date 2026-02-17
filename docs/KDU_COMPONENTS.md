# KDU Component Analysis

This document outlines the purpose and functionality of the three main architectural components of the KDU (Kernel Driver Utility) project.

## 1. Hamakaze (Destroyer)
**Role:** Main Orchestrator / CLI Application
**Output:** `kdu.exe`

Hamakaze is the central component of the KDU project. It acts as the primary user interface and logic controller for the entire framework.

- **Responsibilities:**
    - **Command Line Interface:** Parses user arguments (e.g., `-map`, `-prv`, `-dse`).
    - **Provider Management:** interfacing with the driver database to select and load the appropriate vulnerable driver.
    - **Exploitation Logic:** Implements the core logic for the Bring Your Own Vulnerable Driver (BYOVD) attack chain, including:
        - Checking system compatibility and features (e.g., HVCI, OS Build).
        - Loading the vulnerable driver via the Service Control Manager.
        - Executing the specific exploit primitives (Read/Write MSR, Physical Memory, etc.).
        - Disabling Driver Signature Enforcement (DSE).
        - Mapping unsigned drivers into kernel memory.
    - **Diagnostics:** Provides tools for system analysis (e.g., listing drivers, checking Secure Boot status).

## 2. Tanikaze (Destroyer)
**Role:** Vulnerable Driver Database & Resource Store
**Output:** `drv64.dll` (typically)

Tanikaze serves as the data repository for KDU, separating the exploit logic (Hamakaze) from the large collection of vulnerable driver binaries.

- **Responsibilities:**
    - **Driver Repository:** Contains the compressed binary versions of all supported vulnerable drivers as embedded resources (`RCDATA`). Examples include `IDR_INTEL_NAL`, `IDR_RTCORE64`, etc.
    - **Provider Database:** Defines the `gProvEntry` table, which maps provider IDs to their metadata (driver name, device name, shellcode support, etc.).
    - **Modular Design:** By isolating the drivers in a separate DLL, KDU can update its list of supported drivers without needing to recompile or modify the main `kdu.exe` executable. Hamakaze loads this DLL at runtime to extract the required driver.

## 3. Taigei (Submarine Tender)
**Role:** Specialized Helper / Payload
**Output:** `Taigei.dll` (often dropped as `SB_SMBUS_SDK.dll`)

Taigei is a specialized component used to facilitate specific exploitation scenarios that require more than just a direct handle to a driver.

- **Responsibilities:**
    - **ASUS Exploit Helper:** Primarily designed to interface with the ASUS input/output driver (`Asusgio3` / `AsIO.sys`).
    - **Trusted Caller Masquerading:** The ASUS driver checks specifically for trusted caller process names or signatures. Taigei (renamed to `SB_SMBUS_SDK.dll`) likely mimics a legitimate ASUS SDK library to interact with the driver authorizedly.
    - **Deployment:** It is embedded as a resource (`IDR_TAIGEI64`) within Hamakaze (`kdu.exe`) and dropped to disk during execution when the specific provider (e.g., Provider #13 / ASUS) is selected.
