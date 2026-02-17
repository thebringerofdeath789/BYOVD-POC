# Build Instructions for KernelMode Toolkit

## Prerequisites

1. **Visual Studio 2022** with C++ development tools
   - C++17 Standard Library support required
2. **Windows SDK 10.0.26100.0** or later  
3. **MASM (ml64.exe)** - Microsoft Macro Assembler
4. **Administrator privileges** for execution
5. **Windows 10/11 x64** target system

## Security & Compliance
This project enforces the following security mitigations in Release builds:
- **Control Flow Guard (CFG)**: `/guard:cf`
- **Spectre Mitigation**: `/Qspectre`
- **ASLR/DEP**: `/DYNAMICBASE`, `/NXCOMPAT`
- **Warning Level**: Level 4 (`/W4`) treated as errors

## Dependencies

### Required Libraries
- `ntdll.lib` - NT system calls
- `kernel32.lib` - Win32 API
- `user32.lib` - User interface
- `advapi32.lib` - Registry and services
- `psapi.lib` - Process API


### System Requirements
- Visual Studio 2022 Community or higher
- Windows 10 version 1903+ or Windows 11
- Administrator privileges for driver loading
- Test signing enabled OR virtualized environment

## Build Configuration

### 1. Solution Setup
```cmd
# Clone or open the project
cd "C:\Users\admin\Documents\Visual Studio 2022\Projects\BYOVD-POC"
# Open KernelModeCpp.sln in Visual Studio 2022
```

### 2. Project Properties Configuration

**Platform Configuration:**
- Platform: `x64` (REQUIRED - no x86 support)
- Configuration: `Debug` for testing, `Release` for production

**C++ Settings:**
- C++ Language Standard: `C++14`
- Runtime Library: `Multi-threaded (/MT)` for Release
- Optimization: `/O2` for Release builds

**Linker Settings:**
```
Additional Dependencies:
- ntdll.lib
- kernel32.lib  
- user32.lib
- advapi32.lib
- psapi.lib
```

### 3. Assembly File Configuration

**For `asmSyscall.asm` and `Syscall.asm`:**

1. Right-click assembly files → Properties
2. Set **Item Type** to `Custom Build Tool`
3. **Command Line:**
   ```cmd
   ml64 /c /Fo"$(IntDir)%(Filename).obj" "%(FullPath)"
   ```
4. **Outputs:** 
   ```
   $(IntDir)%(Filename).obj
   ```
5. **Additional Include Directories:** `$(ProjectDir)`

### 4. Build Steps

```cmd
# 1. Clean solution
Build → Clean Solution

# 2. Rebuild all
Build → Rebuild Solution

# 3. Verify output
# Check: x64\Debug\BYOVD-POC.exe or x64\Release\BYOVD-POC.exe
```

### 5. Driver File Preparation

**Required Directory Structure:**
```
BYOVD-POC\
├── data\
│   ├── gdrv.bin
│   ├── dbutilcat.bin
│   └── ...
├── Drv\
│   ├── gdrv.sys
│   ├── RTCore64.bin
│   ├── WinRing0x64.bin
│   └── ...
└── x64\Debug\BYOVD-POC.exe
```

**Critical:** Ensure vulnerable driver files exist in `data\` and `Drv\` directories.

## Testing Environment Setup

### Option 1: Test Signing (Recommended for Testing)
```cmd
# Enable test signing (requires reboot)
bcdedit /set testsigning on
shutdown /r /t 0
```

### Option 2: Virtual Machine (Safest)
- Use VMware/VirtualBox with Windows 10/11
- Create snapshot before testing
- Disable Windows Defender in VM

### Option 3: Disabled DSE (Advanced)
```cmd
# Temporarily disable DSE (advanced users only)
bcdedit /set nointegritychecks on
```

## Common Build Issues

### Assembly Build Errors
**Problem:** `asmSyscall.asm` fails to compile
**Solution:** 
1. Ensure MASM is installed with Visual Studio
2. Verify custom build tool configuration
3. Check file encoding (should be ASCII/UTF-8)

### Linker Errors
**Problem:** Unresolved external symbols
**Solution:**
1. Add missing libraries to Additional Dependencies
2. Verify platform is set to x64
3. Ensure Windows SDK is properly installed

### Runtime Errors
**Problem:** Driver fails to load
**Solution:**
1. Run as Administrator
2. Enable test signing
3. Check if antivirus is blocking execution
4. Verify driver files exist in correct directories

## Security Considerations

⚠️ **WARNING:** This toolkit is for educational/research purposes only

### Safe Testing Practices
1. **Always use isolated test environment**
2. **Never run on production systems**
3. **Use VM snapshots for rollback**
4. **Disable network in test VMs**
5. **Monitor system behavior carefully**

### Legal Compliance
- Only use in authorized environments
- Respect applicable laws and regulations
- Follow responsible disclosure for vulnerabilities
- Obtain proper permissions before testing

## Troubleshooting

### Build Issues
1. Clean and rebuild solution
2. Verify all prerequisites installed
3. Check Windows SDK version compatibility
4. Ensure assembly files are properly configured

### Runtime Issues
1. Verify administrator privileges
2. Check test signing status
3. Confirm driver files exist
4. Review Windows Event Logs for errors

### Driver Loading Failures
1. Enable test signing and reboot
2. Use Sysinternals tools to verify driver status
3. Check for conflicting security software
4. Review DSE bypass methods in documentation
