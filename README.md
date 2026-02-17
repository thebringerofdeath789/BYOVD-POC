# KernelMode - Advanced Windows Kernel Exploitation Toolkit

**Author:** [Gregory King](https://github.com/thebringerofdeath789)  
**Repository:** [KernelModeCpp](https://github.com/thebringerofdeath789/KernelModeCpp)  
**Version:** 1.1 (Post-Audit 2026)  
**Date:** February 17, 2026  
**License:** Educational/Research Use Only
**Status:** ✅ Active Development - P0 Critical Fixes Implemented (Jan 2026)

## 🚨 Disclaimer

This project is developed **strictly for educational and security research purposes**. It demonstrates advanced Windows kernel exploitation techniques using Bring Your Own Vulnerable Driver (BYOVD) attacks. The author is not responsible for any misuse of this software. Use only in controlled environments with proper authorization.

## 📋 Table of Contents

- [Overview](#overview)
- [Documentation](#documentation)
- [Current Status](#current-status)
- [Features](#features)
- [Architecture](#architecture)
- [Supported Vulnerable Drivers](#supported-vulnerable-drivers)
- [Installation and Building](#installation-and-building)
- [Usage](#usage)
- [Technical Details](#technical-details)
- [Legal Notice](#legal-notice)
- [References](#references)
- [Contributing](#contributing)

## 🔍 Overview

KernelMode is a comprehensive proof-of-concept toolkit that demonstrates advanced Windows kernel exploitation techniques. It leverages vulnerable signed drivers to establish kernel-level memory read/write primitives, enabling sophisticated attacks typically reserved for kernel-mode operations. The toolkit implements a modular provider-based architecture inspired by the [Kernel Driver Utility (KDU)](https://github.com/hfiref0x/KDU) project.

This project has recently undergone a comprehensive code audit (Jan 2026), addressing critical lifecycle issues, memory leaks, and provider implementation flaws.

## 📚 Documentation

Detailed documentation is available in the `docs/` folder:

*   **[Audit Summary](docs/AUDIT_FINAL_SUMMARY.md)**: Final report of the Jan 2026 code audit.
*   **[Lifecycle Fixes](docs/LIFECYCLE_FIXES_IMPLEMENTED.md)**: Details on implemented critical fixes.
*   **[Technical Workflows](docs/technical_workflow.md)**: Detailed step-by-step explanation of the exploit chain, memory primitives, and DSE bypass logic.
*   **[Build Instructions](docs/BUILD_INSTRUCTIONS.md)**: How to compile the project.
*   **[Architecture Guide](docs/architecture.md)**: Deep dive into the Provider/Manager system and internal logic.
*   **[Roadmap](ROADMAP.md)**: Current project status and future plans.
*   **[Testing](tests/README.md)**: Information about the test suite.

## 🚀 Current Status

As of February 2026, the project has successfully addressed **Priority 0 (Critical)** issues identified during the Jan 2026 audit:

*   ✅ **Memory Safety**: Fixed kernel memory leaks in `ManualMapper`.
*   ✅ **Provider Reliability**: Standardized `RTCore`, `Gdrv`, and `DBUtil` providers with authentic KDU implementation logic (syscalls, handle flags).
*   ✅ **Execution Stability**: Resolved BSOD risks in persistence mechanisms and shellcode execution.
*   ✅ **Build**: Successfully compiles for **Debug x64**.

## ✨ Features

### 🎯 Core Capabilities

- **🔧 Vulnerable Driver Management**
  - Dynamic loading of vulnerable signed drivers
  - Automated service creation and management
  - Provider-based architecture (RTCore, Gdrv, DBUtil, etc.)
  - Support for multiple driver families

- **🧨 Victim Driver Hijacking (New)**
  - Loads a benign signed "Victim" driver (e.g. ProcExp, EchoDrv).
  - Hijacks the Victim's dispatch routines to execute arbitrary kernel shellcode.
  - Stealthy execution vector bypassing simple hooks.

- **🛡️ Driver Signature Enforcement (DSE) Bypass**
  - Patches `g_CiOptions` kernel variable
  - Enables loading of unsigned drivers

- **🤖 Automated Rootkit Loader (SilentRK)**
  - Dedicated `BYOVDManager` for end-to-end attack orchestration.
  - Automated workflow: Load Vulnerable Driver -> Disable DSE -> Load Unsigned Payload (`SilentRK.sys`) -> Restore Security.
  - Supports both Service-based loading and Manual Mapping techniques.

- **🏗️ Manual Driver Mapping**
  - Bypass standard driver loading mechanisms
  - Import resolution and relocation handling
  - PE header obfuscation for stealth

- **🔍 Utilities**
  - PE file parser and analyzer
  - Kernel memory utilities

## �️ Architecture

The project uses a **Provider/Manager** model:

1.  **Manager**: Handles the high-level attack lifecycle (load, exploit, unload).
2.  **Providers**: Specialized implementations for each vulnerable driver (e.g., RTCore, GDRV).
3.  **Resources**: Encrypted external drivers used for the attack.

For a complete technical breakdown, see the **[Architecture Guide](docs/architecture.md)**.

## �🎯 Supported Vulnerable Drivers

| Driver | Vendor | CVE | Technique | Status |
|--------|--------|-----|-----------|--------|
| `gdrv.sys` | GIGABYTE | CVE-2018-19320 | Memory Read/Write | ✅ Active |
| `RTCore64.sys` | Micro-Star (MSI) | CVE-2019-16098 | Memory Read/Write | ✅ Active |
| `DBUtil_2_3.sys` | Dell | CVE-2021-21551 | Memory Read/Write | ✅ Active |

## 🛠️ Installation and Building

Please refer to the **[Build Instructions](docs/BUILD_INSTRUCTIONS.md)** for detailed steps on setting up Visual Studio 2022 and the Windows SDK.

1.  Clone the repository.
2.  Open `KernelModeCpp.sln`.
3.  Select **x64** and **Release**.
4.  Build Solution.

## 🚀 Usage
git clone https://github.com/thebringerofdeath789/KernelModeCpp.git
2. **Open in Visual Studio:**

3. **Configure build settings:**
- Platform: **x64**
- Configuration: **Debug** or **Release**
- C++ Standard: **C++14**

4. **Add required libraries:**
- Right-click project → Properties
- Linker → Input → Additional Dependencies
- Add: `ntdll.lib`

5. **Build the solution:**

### Assembly File Configuration

The `asmSyscall.asm` file requires special configuration:

1. Right-click `asmSyscall.asm` → Properties
2. Set **Item Type** to **Custom Build Tool**
3. **Command Line:**
ml64 /c /Fo"$(IntDir)" /Fe"$(IntDir)asmSyscall.obj" /I"$(SolutionDir)External\Includes" "$(ProjectDir)asmSyscall.asm"
4. **Outputs:** $(IntDir)asmSyscall.obj


### Direct System Calls

The toolkit implements direct system calls to avoid user-mode API hooks. The assembly implementation uses x64 calling conventions:

**Assembly Implementation:**
- RCX = syscall index
- RDX = parameters array  
- R8 = parameter count
- Uses direct syscall instruction to bypass hooks

### DKOM Process Hiding

Process hiding is achieved through Direct Kernel Object Manipulation:

**Steps:**
1. Locate target process in kernel memory using PID
2. Unlink from ActiveProcessLinks doubly-linked list
3. Remove from PspCidTable handle table
4. Process becomes invisible to enumeration tools

**Implementation Overview:**
- Find EPROCESS structure for target PID
- Unlink from ActiveProcessLinks
- Remove from PspCidTable
- Return success status

### DSE Bypass Implementation

Driver Signature Enforcement is bypassed by patching the g_CiOptions kernel variable:

**Process:**
1. Locate ntoskrnl.exe base address
2. Find g_CiOptions variable using pattern scanning
3. Read current enforcement value
4. Clear enforcement bits to disable DSE
5. Write modified value back to kernel

### File System Hooking

File hiding is implemented through IRP (I/O Request Packet) hooking:

**Method:**
- Find NTFS driver object in kernel
- Hook IRP_MJ_DIRECTORY_CONTROL handler
- Install custom handler to filter directory listings
- Hide specified files from enumeration

### ETW Provider Manipulation

Event Tracing for Windows (ETW) providers are disabled to evade detection:

**Technique:**
- Locate ETW threat intelligence provider GUID
- Find provider registration structure
- Disable provider by zeroing callback function
- Prevents telemetry collection by security products

### Manual Driver Mapping

Drivers are manually mapped into kernel memory to bypass standard loading mechanisms:

**Process:**
1. Parse PE headers of target driver
2. Allocate kernel memory for driver image
3. Map sections with proper memory protections
4. Resolve imports from kernel modules
5. Apply relocations for new base address
6. Call driver entry point to initialize

### Compilation Requirements

**Build Environment:**
- C++ Standard: C++14
- Target Architecture: x64 only
- Assembly: MASM64 for syscall stubs
- Dependencies: ntdll.lib for NT API functions
- Compiler: MSVC 14.44 (Visual Studio 2022)

**Key Features:**
- RAII resource management
- Smart pointer usage throughout
- Direct syscall implementation for stealth

## ⚖️ Legal Notice

This software is provided for **educational and authorized security research purposes only**. Users must:

- ✅ Have explicit written permission to test on target systems
- ✅ Use only in controlled, isolated environments  
- ✅ Comply with all applicable laws and regulations
- ❌ Not use for malicious purposes or unauthorized access
- ❌ Not distribute to unauthorized parties

The author disclaims all responsibility for misuse of this software.

## 📚 References

### Primary Inspiration
- **"Kernel Driver Utility (KDU)"** by hFiref0x - [GitHub](https://github.com/hfiref0x/KDU)
  - This project is heavily inspired by and builds upon the techniques demonstrated in KDU
  - Provider architecture and vulnerable driver exploitation methods derived from KDU research

### CVE References
- **CVE-2018-19320** - GIGABYTE gdrv.sys Memory Corruption
- **CVE-2019-16098** - MSI RTCore64.sys Privilege Escalation  
- **CVE-2021-21551** - Dell DBUtil_2_3.sys Memory Corruption

### Technical Documentation
- **"Bring Your Own Vulnerable Driver"** - MITRE ATT&CK T1068
- **Windows Internals** by Russinovich & Solomon
- **Windows Kernel Programming** by Pavel Yosifovich

## 🤝 Contributing

Contributions are welcome for educational and research purposes:

1. **Fork the repository** at [KernelModeCpp](https://github.com/thebringerofdeath789/KernelModeCpp)
2. **Create a feature branch**
3. **Implement your enhancement**
4. **Add comprehensive documentation**
5. **Submit a pull request**

### Development Guidelines

- Follow existing code style and conventions
- Add comprehensive comments and documentation
- Include proper error handling
- Test thoroughly in isolated environments
- Ensure compliance with educational use restrictions

---

**⚠️ Remember: With great power comes great responsibility. Use this knowledge ethically and legally.**

**© 2025 Gregory King. All rights reserved.**

**Repository:** https://github.com/thebringerofdeath789/KernelModeCpp
