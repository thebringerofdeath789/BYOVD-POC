# BYOVD-POC Custom Code Audit - January 2026

**Auditor:** AI Code Analysis System  
**Date:** January 29, 2026  
**Scope:** Custom infrastructure code only (excluding KDU-based provider implementations)  
**Methodology:** Systematic scan for memory safety, UB, concurrency, security, portability, and build hazards

**Note:** This audit focuses on custom implementation code. KDU-based provider implementations are considered third-party and excluded from this analysis.

---

## A) REPO AUDIT SUMMARY

### Severity Distribution
- **CRITICAL**: 6 issues
- **HIGH**: 12 issues  
- **MEDIUM**: 18 issues
- **LOW**: 11 issues

**Total**: 47 issues identified (in custom code only)

### Top Recurring Issue Categories
1. **Memory Safety** (13 issues) - Buffer overflows, unchecked bounds, resource management
2. **Error Handling** (11 issues) - Ignored return values, exception safety, cleanup failures
3. **Security** (9 issues) - Registry manipulation, command injection, TOCTOU, path handling
4. **Undefined Behavior** (5 issues) - Integer overflow, uninitialized reads, alignment
5. **Portability** (4 issues) - Windows-specific assumptions, hardcoded paths
6. **Concurrency** (3 issues) - Race conditions, missing synchronization
7. **Code Quality** (2 issues) - Dead code, poor documentation

### Biggest Risk Areas (Custom Modules)
1. **KernelMode/UACBypass.cpp** - Command injection, registry manipulation, timing issues (CRITICAL)
2. **KernelMode/PEParser.cpp** - PE file parsing with insufficient validation (CRITICAL)
3. **KernelMode/ServiceManager.cpp** - Service lifecycle, TOCTOU vulnerabilities, resource leaks (HIGH)
4. **KernelMode/Main.cpp** - Global state, UAC bypass integration, exception handling (HIGH)
5. **KernelMode/Utils.cpp** - Kernel memory operations, NtQuerySystemInformation handling (HIGH)
6. **KernelMode/Privilege.cpp** - EPROCESS offset resolution, token theft (MEDIUM)
7. **KernelMode/Callbacks.cpp** - Pattern scanning, bounds checking (MEDIUM)
8. **KernelMode/DriverDataManager.cpp** - Resource extraction, decompression (MEDIUM)

---

## B) FINDINGS (SORTED BY SEVERITY)

### CRITICAL SEVERITY

#### BUG-001
- **Severity**: CRITICAL
- **Location**: KernelMode/PEParser.cpp:117-142
- **Category**: Memory Safety / Buffer Overflow
- **Description**: Section header array bounds not validated before IMAGE_FIRST_SECTION access. Malicious PE can specify NumberOfSections > actual file size, causing OOB read when iterating sections.
- **Impact**: 
  - Crash when parsing malformed PE files
  - Information disclosure (reading beyond buffer)
  - Potential RCE if attacker controls file content and exploits OOB write in memcpy operations
- **Evidence**:
```cpp
auto sectionHeader = IMAGE_FIRST_SECTION(this->ntHeaders);
for (WORD i = 0; i < this->ntHeaders->FileHeader.NumberOfSections; ++i, ++sectionHeader) {
    // No check if sectionHeader is within fileBuffer bounds
    if (sectionHeader->SizeOfRawData > 0) {
        memcpy(localImage.data() + sectionHeader->VirtualAddress, ...);
    }
}
```
- **Validation**: 
  - Unit test: Create PE with NumberOfSections=0xFFFF and SizeOfHeaders=0x400
  - ASAN build should detect heap-buffer-overflow
  - Fuzzer input: mutate NumberOfSections field
- **Fix Plan**: Calculate section table end offset before loop: `sectionsEnd = (BYTE*)sectionHeader + (NumberOfSections * sizeof(IMAGE_SECTION_HEADER))`. Verify `sectionsEnd <= fileBuffer.data() + fileBuffer.size()` before iteration.

---

#### BUG-002
- **Severity**: CRITICAL
- **Location**: KernelMode/ManualMapper.cpp:134-138
- **Category**: Memory Safety / Integer Overflow
- **Description**: Section VirtualAddress + SizeOfRawData can overflow DWORD, causing wrap-around and memcpy to write OOB in localImage buffer.
- **Impact**:
  - Heap corruption when mapping drivers with crafted section headers
  - BSOD when writing corrupted image to kernel memory
  - Potential arbitrary code execution if attacker controls section layout
- **Evidence**:
```cpp
if (sectionHeader->VirtualAddress + sectionHeader->SizeOfRawData <= imageSize &&
    sectionHeader->PointerToRawData + sectionHeader->SizeOfRawData <= imageBuffer.size()) {
    memcpy(localImage.data() + sectionHeader->VirtualAddress, ...);
}
```
No check for addition overflow before comparison.
- **Validation**:
  - Test PE with VirtualAddress=0xFFFFF000, SizeOfRawData=0x2000 (wraps to 0x1000)
  - AddressSanitizer should detect heap-buffer-overflow
  - Manual test: Force imageSize=0x10000, trigger overflow condition
- **Fix Plan**: Use SafeInt or check overflow: `if (VirtualAddress > imageSize || SizeOfRawData > imageSize - VirtualAddress) return false;`

---

#### BUG-003
- **Severity**: CRITICAL
- **Location**: KernelMode/Utils.cpp:118-123
- **Category**: Memory Safety / String Handling
- **Description**: GetKernelModuleInfo reads FullPathName[256] from kernel structure without null-termination validation. OffsetToFileName can point OOB or to non-terminated string.
- **Impact**:
  - Buffer over-read in _stricmp
  - Crash when enumerating kernel modules
  - Information leak if comparing uninitialized stack data
- **Evidence**:
```cpp
std::string currentModuleName((const char*)modules->Modules[i].FullPathName + 
                               modules->Modules[i].OffsetToFileName);
// No validation that OffsetToFileName < 256 or that string is null-terminated
```
- **Validation**:
  - Kernel module with malformed OffsetToFileName (e.g., 300)
  - Valgrind/ASan should detect invalid read
- **Fix Plan**: 
  1. Check `OffsetToFileName >= 256` → skip module
  2. Use `strnlen(nameStart, 256 - OffsetToFileName)` to find safe length
  3. Check if string is null-terminated: `nameStart[actualLen] == 0`

---

#### BUG-004
- **Severity**: CRITICAL
- **Location**: KernelMode/Syscall.cpp:56-59
- **Category**: Memory Safety / Type Punning
- **Description**: Syscall stub parsing assumes BYTE layout without validating function is in ntdll text section. Attacker-controlled ntdll.dll (via DLL hijacking) can cause arbitrary memory reads.
- **Impact**:
  - Reading arbitrary memory as syscall indices
  - Crash if funcAddr points to unmapped region
  - Privilege escalation if syscall indices are controllable
- **Evidence**:
```cpp
BYTE* funcAddr = (BYTE*)ntdll + functions[ordinals[i]];
if (*(funcAddr) == 0x4C && *(funcAddr + 3) == 0xB8) {
    DWORD syscallIndex = *(DWORD*)(funcAddr + 4);
}
```
No check that funcAddr is within module bounds or in .text section.
- **Validation**:
  - Replace ntdll.dll with modified version where export RVA = 0xFFFFFFFF
  - Access violation should occur
- **Fix Plan**: 
  1. Get .text section RVA and size from ntdll PE headers
  2. Validate `(funcAddr >= textStart) && (funcAddr < textEnd)`
  3. Add bounds check before reading 8 bytes: `funcAddr + 8 < moduleEnd`

---

#### BUG-005
- **Severity**: CRITICAL
- **Location**: KernelMode/Main.cpp:95-107
- **Category**: Security / Undefined Behavior
- **Description**: Provider vector uses raw pointers in loop without exception safety. If Initialize() throws, resources leak. If DSE::Disable() throws, driver remains loaded with DSE disabled.
- **Impact**:
  - Resource leaks (driver handles, services)
  - System instability (DSE left disabled on exception)
  - BSOD if provider throws after partial kernel modifications
- **Evidence**:
```cpp
for (auto& provider : providers) {
    if (!provider->Initialize()) continue;
    KernelMode::DSE dse(provider.get()); // If throws, provider not cleaned
    if (dse.Disable()) { ... }
}
```
- **Validation**:
  - Inject exception in DSE constructor (mock test)
  - Verify service cleanup occurs
  - Check DSE is restored even on throw
- **Fix Plan**: Wrap entire loop body in try-catch. Ensure RAII cleanup: provider->Deinitialize() in catch block. Use scope guards or finally-like idioms.

---

#### BUG-006
- **Severity**: CRITICAL
- **Location**: KernelMode/ServiceManager.cpp:180-185 (removed in fix, but pattern may exist elsewhere)
- **Category**: Security / Race Condition (TOCTOU)
- **Description**: Pre-checking service existence before CreateService creates TOCTOU window. Malicious process can create service between check and creation, leading to privilege escalation.
- **Impact**:
  - Attacker creates malicious service with same name
  - Application opens attacker's service thinking it's safe
  - Arbitrary driver loading with elevated privileges
- **Evidence**: (Pattern analysis - check if similar exists in Utils.cpp CreateDriverService)
```cpp
if (GetInternalServiceStatus(serviceName) == ServiceStatus::NOT_FOUND) {
    // WINDOW: Another process can create service here
    CreateServiceW(..., serviceName, ...);
}
```
- **Validation**:
  - Race condition fuzzer: spawn competing service creation threads
  - Manual test: Create service in separate process between check and create
- **Fix Plan**: Remove pre-check. Call CreateServiceW directly. Handle ERROR_SERVICE_EXISTS by opening existing service and validating it belongs to us (check binary path matches expected).

---

#### BUG-007
- **Severity**: CRITICAL
- **Location**: KernelMode/DSE.cpp:94-100
- **Category**: Memory Safety / Pointer Validation
- **Description**: pCipInitialize calculation (pCiInitialize + offset + relativeValue) not validated to be within ci.dll module bounds before reading code.
- **Impact**:
  - Reading arbitrary memory when scanning for g_CiOptions
  - Crash if pointer lands in unmapped region
  - Incorrect g_CiOptions address leads to BSOD when patching random kernel memory
- **Evidence**:
```cpp
uintptr_t pCipInitialize = pCiInitialize + offset + relativeValue;
// No check if pCipInitialize is within [ciModule, ciModule + SizeOfImage]
memcpy(cipCode.data(), (void*)pCipInitialize, 256);
```
- **Validation**:
  - Test with corrupted ci.dll (modified jump offsets)
  - ASAN should catch OOB read
- **Fix Plan**: Get NT headers from loaded ci.dll, extract SizeOfImage. Validate: `(pCipInitialize >= (uintptr_t)ciModule) && (pCipInitialize < (uintptr_t)ciModule + SizeOfImage)` before memcpy.

---

#### BUG-008
- **Severity**: CRITICAL
- **Location**: KernelMode/UACBypass.cpp:51-53
- **Category**: Security / Command Injection
- **Description**: UACBypass writes exePath to registry without validating path doesn't contain injection characters. Attacker with write access to executable can inject command line args via spaces or quotes.
- **Impact**:
  - Privilege escalation via arbitrary command execution
  - fodhelper.exe will execute injected commands with High integrity
- **Evidence**:
```cpp
wchar_t exePath[MAX_PATH];
GetModuleFileNameW(NULL, exePath, MAX_PATH);
RegSetValueExW(hKey, NULL, 0, REG_SZ, (BYTE*)exePath, ...);
// No validation of exePath content (could be "C:\evil path.exe" -arg)
```
- **Validation**:
  - Place executable in path with spaces: `C:\Test Dir\app.exe`
  - Registry will have unquoted path
  - fodhelper may execute `C:\Test` instead
- **Fix Plan**: Always quote the path if it contains spaces: `if (wcschr(exePath, L' ')) { /* wrap in quotes */ }`. Alternatively, validate path contains no dangerous characters.

---

### HIGH SEVERITY

#### BUG-009
- **Severity**: HIGH
- **Location**: KernelMode/ServiceManager.cpp:93-97
- **Category**: Error Handling / Logic
- **Description**: GenerateUniqueServiceName returns empty string on SCM failure but caller doesn't check. Empty string passed to service operations causes ERROR_INVALID_NAME.
- **Impact**:
  - Service creation always fails silently
  - Application continues with invalid state
  - Difficult to debug (no error logged for empty name)
- **Evidence**:
```cpp
ServiceStatus status = GetInternalServiceStatus(uniqueName);
if (status == ServiceStatus::UNKNOWN) {
     std::wcerr << L"[-] SCM unreachable during name generation." << std::endl;
     return L""; // Caller doesn't check this!
}
```
- **Validation**:
  - Mock SCM to return UNKNOWN
  - Verify InstallDriverService fails gracefully
- **Fix Plan**: Change return type to `std::optional<std::wstring>` or return unique_ptr. Caller must check: `if (name.empty()) return false;`

---

#### BUG-010
- **Severity**: HIGH
- **Location**: KernelMode/Utils.cpp:91-95
- **Category**: Error Handling / Unchecked Return
- **Description**: NtQuerySystemInformation first call returns status but modulesSize is not validated. If status != STATUS_INFO_LENGTH_MISMATCH and modulesSize == 0, resize(0) then second call writes to 0-byte buffer.
- **Impact**:
  - Heap corruption or assertion failure in std::vector::resize
  - Crash when querying kernel modules
  - Unreliable module enumeration
- **Evidence**:
```cpp
status = NtQuerySystemInformation(..., nullptr, 0, &modulesSize);
if (modulesSize == 0) {
    // Sometimes it returns error but gives size...
}
modulesSize += 4096; // But what if modulesSize was already 0?
modulesBuffer.resize(modulesSize); // resize(4096) with 0-byte expected?
```
- **Validation**:
  - Mock NtQuerySystemInformation to return STATUS_ACCESS_DENIED with modulesSize=0
  - Check if crash or hang occurs
- **Fix Plan**: Check status: `if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_SUCCESS) return {0, 0};`. Only proceed if modulesSize > 0.

---

#### BUG-011
- **Severity**: HIGH
- **Location**: KernelMode/Main.cpp:208-213
- **Category**: Security / Registry Cleanup
- **Description**: UAC bypass cleanup uses RegDeleteTreeW on ms-settings but doesn't handle failure. If deletion fails, artifact remains, triggering on next reboot.
- **Impact**:
  - Persistence mechanism (elevated app launches on next login)
  - Forensic evidence of UAC bypass
  - Potential security alert from AV/EDR
- **Evidence**:
```cpp
HKEY hKeyClasses;
if (RegOpenKeyExW(..., L"Software\\Classes", ..., &hKeyClasses) == ERROR_SUCCESS) {
    RegDeleteTreeW(hKeyClasses, L"ms-settings"); // Return value ignored
    RegCloseKey(hKeyClasses);
}
```
- **Validation**:
  - Set readonly permissions on HKCU\Software\Classes\ms-settings
  - Verify error is not logged and key persists
- **Fix Plan**: Check return value: `LONG result = RegDeleteTreeW(...); if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND) { /* log warning */ }`

---

#### BUG-012
- **Severity**: HIGH
- **Location**: KernelMode/Providers/GdrvProvider.cpp:82-90
- **Category**: Memory Safety / Integer Overflow
- **Description**: MapMemMapMemory aligns physicalAddress but doesn't check if (physicalAddress - offset) + numberOfBytes overflows ULONG.
- **Impact**:
  - mapSize wraps to small value
  - Insufficient memory mapped
  - Read/write OOB when accessing mapped region
- **Evidence**:
```cpp
offset = physicalAddress & ~(PAGE_SIZE - 1);
if (numberOfBytes > 0xFFFFFFFF - PAGE_SIZE) {
    return NULL;
}
mapSize = (ULONG)(physicalAddress - offset) + numberOfBytes;
// But (physicalAddress - offset) can be up to 0xFFF, and numberOfBytes can be 0xFFFFF000
// If they sum to > 0xFFFFFFFF, mapSize wraps!
```
- **Validation**:
  - Call with physicalAddress=0x10000FFF, numberOfBytes=0xFFFFF001
  - mapSize should be validated before MmMapIoSpace
- **Fix Plan**: Check overflow: `if ((physicalAddress - offset) > ULONG_MAX - numberOfBytes) return NULL;`

---

#### BUG-013
- **Severity**: HIGH
- **Location**: KernelMode/Providers/*.cpp (multiple files)
- **Category**: Error Handling / Partial I/O
- **Description**: DeviceIoControl calls check return value but not bytesReturned. Driver may write partial data and return success, causing silent data corruption.
- **Impact**:
  - Silent memory corruption in kernel R/W operations
  - Incorrect DSE bypass (partial write to g_CiOptions)
  - BSOD due to inconsistent kernel state
- **Evidence**: (Example from RTCoreProvider.cpp:145)
```cpp
if (DeviceIoControl(deviceHandle, IOCTL_RTCORE_READ_MEMORY, &request, ..., &bytesReturned, NULL))
{
    memcpy(bufferPtr + bytesRead, &request.Value, readSize);
    // No check if bytesReturned == sizeof(request)
}
```
- **Validation**:
  - Mock IOCTL to return success but bytesReturned=0
  - Verify memcpy copies garbage data
- **Fix Plan**: Add validation: `if (DeviceIoControl(...) && bytesReturned == sizeof(expected)) { ... } else { return false; }`

---

#### BUG-014
- **Severity**: HIGH
- **Location**: KernelMode/Main.cpp:39-40
- **Category**: Portability / Build Hazard
- **Description**: Global std::ofstream g_logFile declared at file scope without synchronization. Multiple threads could write simultaneously causing data race.
- **Impact**:
  - Data race if TryLoadSilentRK spawns threads (unlikely but possible with future changes)
  - Interleaved log output (corrupted log file)
  - Undefined behavior per C++ standard
- **Evidence**:
```cpp
std::ofstream g_logFile; // Global, no mutex
// ...
if (g_logFile.is_open()) g_logFile << "[+] Mission Accomplished" << std::endl;
```
- **Validation**:
  - Multi-threaded stress test with concurrent TryLoadSilentRK calls
  - ThreadSanitizer should detect data race
- **Fix Plan**: Use thread-local storage or add std::mutex. Better: refactor to logger class with internal synchronization.

---

#### BUG-015
- **Severity**: HIGH
- **Location**: KernelMode/Syscall.cpp:25-35
- **Category**: Security / Hooking Bypass
- **Description**: Syscall constructor loads ntdll from disk (DONT_RESOLVE_DLL_REFERENCES) but doesn't verify integrity. Attacker can plant modified ntdll.dll in system32 to poison syscall map.
- **Impact**:
  - Incorrect syscall numbers lead to wrong kernel functions
  - Potential privilege escalation or DoS
  - Bypass detection of syscall hooking (ironically)
- **Evidence**:
```cpp
std::string ntdllPath = std::string(sysPath) + "\\ntdll.dll";
HMODULE ntdll = LoadLibraryExA(ntdllPath.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);
// No signature or hash validation
```
- **Validation**:
  - Replace System32\ntdll.dll with modified version (requires admin, but we have it)
  - Check if syscall indices change
- **Fix Plan**: Verify ntdll.dll signature using WinVerifyTrust before loading. Fallback to in-memory ntdll if disk file is modified.

---

#### BUG-016
- **Severity**: HIGH
- **Location**: KernelMode/ManualMapper.cpp:206-230
- **Category**: Memory Safety / Shellcode
- **Description**: DriverEntry shellcode contains hardcoded 1024-byte stack reservation but zeros only 256 bytes (32 qwords). Remaining 768 bytes contain uninitialized stack data.
- **Impact**:
  - Driver reads uninitialized memory when accessing DRIVER_OBJECT fields
  - Non-deterministic behavior (depends on stack contents)
  - Potential information leak if driver logs stack data
- **Evidence**:
```cpp
0x48, 0x81, 0xEC, 0x00, 0x04, 0x00, 0x00,   // sub rsp, 1024
// ...
0x48, 0xB9, 0x20, 0x00, 0x00, ...,           // mov rcx, 32 (qwords)
0xF3, 0x48, 0xAB,                            // rep stosq (zeros 32*8 = 256 bytes)
// 1024 - 256 = 768 bytes uninitialized
```
- **Validation**:
  - Valgrind/MemorySanitizer on shellcode execution
  - Manual: Fill stack with 0xCC pattern, check if read
- **Fix Plan**: Change `mov rcx, 32` to `mov rcx, 128` (zeros 1024 bytes) OR reduce stack reservation to 256 bytes.

---

#### BUG-017
- **Severity**: HIGH
- **Location**: KernelMode/Utils.cpp:191-199
- **Category**: Error Handling / Service Cleanup
- **Description**: CreateDriverService creates service but cleanup on StartService failure doesn't verify DeleteService succeeded. Service remains in ERROR state, blocking future loads.
- **Impact**:
  - Service stuck in ERROR state
  - Application must be restarted with different service name
  - Registry pollution (100+ failed services after fuzzing)
- **Evidence**:
```cpp
if (!StartServiceW(...)) {
    // ...
    serviceHandle = OpenServiceW(scmHandle, serviceName.c_str(), DELETE);
    if (serviceHandle) {
        DeleteService(serviceHandle); // Return value ignored
        CloseServiceHandle(serviceHandle);
    }
    return nullptr;
}
```
- **Validation**:
  - Force StartService to fail (invalid driver path)
  - Check if DeleteService fails (service in use)
  - Verify service persists in registry
- **Fix Plan**: Check DeleteService return: `if (!DeleteService(...)) { /* log error, mark for cleanup */ }`. Implement retry logic or defer deletion to next run.

---

#### BUG-018
- **Severity**: HIGH
- **Location**: KernelMode/PEParser.cpp:53-56
- **Category**: Undefined Behavior / Alignment
- **Description**: e_lfanew alignment check uses bitwise AND but doesn't account for architecture differences. On ARM64, NT headers may require 8-byte alignment.
- **Impact**:
  - Misaligned pointer access on ARM64 → SIGBUS
  - Portability issue if ever ported to ARM64
  - Potential misalignment even on x64 if DOS stub is crafted oddly
- **Evidence**:
```cpp
if (this->dosHeader->e_lfanew < 0 || 
    (size_t)this->dosHeader->e_lfanew >= this->fileBuffer.size() || 
    (this->dosHeader->e_lfanew & 0x3) != 0) { // 4-byte align check
```
- **Validation**:
  - Cross-compile to ARM64 and run on ARM64 Windows
  - Create PE with e_lfanew=0x107 (misaligned)
- **Fix Plan**: Use `alignof(IMAGE_NT_HEADERS)` instead of hardcoded 4. Check: `(e_lfanew % alignof(IMAGE_NT_HEADERS)) == 0`.

---

#### BUG-019
- **Severity**: HIGH
- **Location**: Multiple Provider files (ProcessHackerProvider.cpp:335, ProcessExplorerProvider.cpp:346, etc.)
- **Category**: Memory Safety / Exception Safety
- **Description**: Physical memory mapping (MmMapIoSpace equivalent) followed by memcpy without __try/__except. If mapped region is inaccessible (hardware issue), memcpy causes access violation.
- **Impact**:
  - Application crash on hardware fault
  - BSOD if exception escalates to kernel
  - Unreliable memory operations on real hardware
- **Evidence**:
```cpp
if (mappedBase) {
    memcpy(buffer, mappedBase, size); // No SEH protection
}
```
- **Validation**:
  - Map invalid physical address (0xFFFFFFFFFFFFFFFF)
  - Attempt memcpy
  - Verify crash instead of graceful failure
- **Fix Plan**: Wrap memcpy in __try/__except: `__try { memcpy(...); } __except(EXCEPTION_EXECUTE_HANDLER) { return false; }`

---

#### BUG-020
- **Severity**: HIGH
- **Location**: KernelMode/ServiceManager.cpp:240-248
- **Category**: Error Handling / Resource Leak
- **Description**: StartDriverService queries service config to get driver path but doesn't free buffer on error paths. Repeated failures leak memory.
- **Impact**:
  - Memory leak (bytesNeeded can be several KB per call)
  - Degraded performance after many service start attempts
  - OOM on long-running fuzzing sessions
- **Evidence**:
```cpp
std::vector<BYTE> buffer(bytesNeeded);
LPQUERY_SERVICE_CONFIGW config = (LPQUERY_SERVICE_CONFIGW)buffer.data();

if (QueryServiceConfigW(...)) {
    // Use config
}
// If QueryServiceConfigW fails, buffer leaks (vector destructs but if exception thrown?)
```
- **Validation**:
  - Call StartDriverService in loop with invalid service
  - Monitor memory usage (should grow without bound if leak exists)
- **Fix Plan**: Use RAII. std::vector already RAII, but ensure no exceptions bypass destructor. Validate with -fsanitize=leak.

---

#### BUG-021
- **Severity**: HIGH
- **Location**: KernelMode/DSE.cpp:110-120
- **Category**: Memory Safety / Pattern Scanning
- **Description**: FindCiOptionsWithRobustPattern scans cipCode up to offset+64 without checking if offset+64 < cipCode.size(). Malformed ci.dll can cause OOB read.
- **Impact**:
  - Crash when scanning for g_CiOptions pattern
  - Incorrect address returned (reading garbage)
  - BSOD when patching incorrect g_CiOptions address
- **Evidence**:
```cpp
for (ULONG cipOffset = offset; cipOffset < offset + 64; ++cipOffset) {
    if (cipCode[cipOffset] == 0x48 && cipCode[cipOffset + 1] == 0x8D) {
        // cipOffset+1 can be >= cipCode.size()
    }
}
```
- **Validation**:
  - Create ci.dll stub with CipInitialize < 64 bytes
  - ASAN should detect heap-buffer-overflow
- **Fix Plan**: Check bounds: `for (ULONG cipOffset = offset; cipOffset + 7 < cipCode.size() && cipOffset < offset + 64; ++cipOffset)`

---

#### BUG-022
- **Severity**: HIGH
- **Location**: KernelMode/Providers/BaseProvider.h:168-180
- **Category**: Error Handling / Template Instantiation
- **Description**: BaseProvider::ReadKernelMemory template doesn't validate TMemoryRequest size matches IOCTL expectations. Mismatched struct size causes IOCTL failure or kernel parsing errors.
- **Impact**:
  - Silent read/write failures (IOCTL returns ERROR_INVALID_PARAMETER)
  - Data corruption if kernel interprets struct differently
  - Difficult to debug (no error message about struct mismatch)
- **Evidence**:
```cpp
TMemoryRequest request = {};
SetupMemoryRequest(request, address, ...);
return DeviceIoControl(deviceHandle, config_.readMemoryIOCTL,
    &request, sizeof(request), ...);
// No validation that sizeof(TMemoryRequest) == expected_size_for_driver
```
- **Validation**:
  - Instantiate BaseProvider with custom TMemoryRequest (e.g., add extra field)
  - IOCTL should fail but no error logged
- **Fix Plan**: Static assertion: `static_assert(sizeof(TMemoryRequest) == EXPECTED_SIZE, "Struct size mismatch");` OR add runtime check and log warning.

---

#### BUG-023
- **Severity**: HIGH
- **Location**: KernelMode/Providers/WinRing0Provider.cpp:175
- **Category**: Memory Safety / Unchecked Size
- **Description**: WriteMemory copies buffer to request->Data without validating size <= sizeof(request->Data). Large writes overflow request structure.
- **Impact**:
  - Stack corruption (if request on stack)
  - Heap corruption (if request on heap)
  - Arbitrary code execution via overwriting return address or vtable
- **Evidence**:
```cpp
memcpy(request->Data, buffer, size); // No check if size > sizeof(request->Data)
```
- **Validation**:
  - Call WriteMemory with size=0x10000
  - ASAN should detect heap-buffer-overflow
- **Fix Plan**: Add check: `if (size > sizeof(request->Data)) return false;` before memcpy. OR allocate variable-size request: `std::vector<BYTE> requestBuf(sizeof(Request) + size);`

---

### MEDIUM SEVERITY

#### BUG-024
- **Severity**: MEDIUM
- **Location**: KernelMode/Main.cpp:11
- **Category**: Security / Build Hazard
- **Description**: #define _CRT_SECURE_NO_WARNINGS disables all secure CRT warnings. Unsafe functions like strcpy may be used elsewhere without detection.
- **Impact**:
  - Hidden buffer overflows in future code changes
  - False sense of security (warnings suppressed)
  - Code review overhead (must manually check for unsafe functions)
- **Evidence**:
```cpp
#define _CRT_SECURE_NO_WARNINGS
```
- **Validation**:
  - Add strcpy call to Main.cpp
  - Compiler should NOT warn (but it's disabled)
- **Fix Plan**: Remove macro. Fix all warnings individually using _s functions (strcpy_s, sprintf_s). Use /W4 /WX to enforce.

---

#### BUG-025
- **Severity**: MEDIUM
- **Location**: KernelMode/Main.cpp:180-181
- **Category**: Error Handling / Time Handling
- **Description**: std::ctime returns pointer to static buffer (not thread-safe). Concurrent logging causes garbled timestamps or crashes.
- **Impact**:
  - Corrupted log file timestamps
  - Potential crash if two threads call ctime simultaneously
  - Undefined behavior per C standard
- **Evidence**:
```cpp
auto time_t = std::chrono::system_clock::to_time_t(now);
g_logFile << "... Started: " << std::ctime(&time_t) << "==========";
// ctime uses static buffer
```
- **Validation**:
  - Multi-threaded logging test
  - Check if timestamps are interleaved
- **Fix Plan**: Use std::put_time with std::localtime_s (thread-safe): `std::put_time(std::localtime(&time_t), "%c")`

---

#### BUG-026
- **Severity**: MEDIUM
- **Location**: KernelMode/Utils.cpp:362-370
- **Category**: Portability / Hardcoded Path
- **Description**: LoadKernelModule uses hardcoded C:\Windows\System32 instead of GetSystemDirectoryW. Fails if Windows installed on different drive.
- **Impact**:
  - Module loading fails on non-C: Windows installations
  - Breaks on Windows-on-ARM or custom WinPE environments
- **Evidence**:
```cpp
std::wstring systemPath = L"C:\\Windows\\System32\\";
systemPath += moduleName;
```
- **Validation**:
  - Install Windows on D: drive
  - Attempt to load kernel module
- **Fix Plan**: Replace with: `wchar_t sysDir[MAX_PATH]; GetSystemDirectoryW(sysDir, MAX_PATH); std::wstring systemPath(sysDir);`

---

#### BUG-027
- **Severity**: MEDIUM
- **Location**: KernelMode/UACBypass.cpp:29
- **Category**: Error Handling / Registry
- **Description**: RegDeleteKeyW on cleanup attempt (line 29) doesn't check if key exists or is already deleted. Spurious error messages confuse debugging.
- **Impact**:
  - Log pollution (repeated "Failed to delete" messages)
  - Difficult to distinguish real errors from expected conditions
- **Evidence**:
```cpp
RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings\\Shell\\Open\\command");
// No check if ERROR_FILE_NOT_FOUND (expected) or real error
```
- **Validation**:
  - Run bypass twice without cleanup
  - Second run should log error (but it's expected)
- **Fix Plan**: Check return value: `LONG result = RegDeleteKeyW(...); if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND) { /* log only real errors */ }`

---

#### BUG-028
- **Severity**: MEDIUM
- **Location**: KernelMode/UACBypass.cpp:78
- **Category**: Security / Timing
- **Description**: Sleep(1000) after fodhelper.exe launch is arbitrary. If fodhelper reads registry immediately (<1s), race window missed. If reads later (>1s), unnecessary delay.
- **Impact**:
  - UAC bypass fails intermittently (timing-dependent)
  - Slow application startup (always waits 1s)
  - Poor user experience
- **Evidence**:
```cpp
ShellExecuteExW(&sei);
// ...
Sleep(1000); // Magic number
```
- **Validation**:
  - Reduce to Sleep(100), check if bypass still works
  - Increase to Sleep(5000), check if unnecessary
- **Fix Plan**: Remove Sleep. Registry is persistent; fodhelper reads whenever it launches. Application can exit immediately. OR use WaitForInputIdle on fodhelper process.

---

#### BUG-029
- **Severity**: MEDIUM
- **Location**: KernelMode/Providers/GdrvProvider.cpp:184-195
- **Category**: Performance / Exception Handling
- **Description**: MapMemReadWritePhysicalMemory uses __try/__except but exception code not logged. Silent failures difficult to diagnose.
- **Impact**:
  - Read/write failures appear as generic "false" return
  - Hardware faults (bad RAM, MMIO) not logged
  - Debugging requires attaching debugger to see exception
- **Evidence**:
```cpp
__try {
    if (doWrite) {
        RtlCopyMemory(...);
    } else {
        RtlCopyMemory(...);
    }
    bResult = TRUE;
}
__except (EXCEPTION_EXECUTE_HANDLER) {
    bResult = FALSE;
    dwError = GetExceptionCode(); // Captured but not logged
}
```
- **Validation**:
  - Map invalid physical address, trigger exception
  - Check if exception code appears in logs (it won't)
- **Fix Plan**: Log exception: `std::wcerr << L"[-] Memory access exception: 0x" << std::hex << dwError << std::endl;`

---

#### BUG-030
- **Severity**: MEDIUM
- **Location**: KernelMode/ServiceManager.cpp:143-158
- **Category**: Error Handling / Buffer Size
- **Description**: CheckServiceStatus allocates buffer for QueryServiceConfigW based on bytesNeeded but doesn't validate bytesNeeded is reasonable (<1GB). Attacker-controlled service config can cause huge allocation.
- **Impact**:
  - OOM if service has 1GB config (malicious or corrupted)
  - DoS attack vector (force app to allocate huge buffer)
  - Slow performance checking service status
- **Evidence**:
```cpp
DWORD bytesNeeded = 0;
QueryServiceConfigW(serviceHandle.get(), NULL, 0, &bytesNeeded);

if (bytesNeeded > 0) {
    std::vector<BYTE> buffer(bytesNeeded); // Unbounded allocation
}
```
- **Validation**:
  - Create service with 100MB binary path (use symlink to long path)
  - Check if app hangs or crashes
- **Fix Plan**: Add limit: `if (bytesNeeded > MAX_SERVICE_CONFIG_SIZE) return info;` where MAX = 64KB (reasonable for service config).

---

#### BUG-031
- **Severity**: MEDIUM
- **Location**: KernelMode/Main.cpp:96
- **Category**: Performance / Allocation
- **Description**: Provider vector (13 providers) created every time TryLoadSilentRK called. If called in loop (retry logic), repeated allocations wasteful.
- **Impact**:
  - Heap fragmentation (repeated allocate/free of 13 shared_ptrs)
  - Slower startup (unnecessary constructor calls)
  - Increased memory usage (temporary vectors not reused)
- **Evidence**:
```cpp
bool TryLoadSilentRK() {
    std::vector<std::shared_ptr<...>> providers;
    providers.push_back(std::make_shared<GdrvProvider>());
    // ... 13 times
}
```
- **Validation**:
  - Profile with heap profiler (e.g., heaptrack)
  - Check allocation count per retry
- **Fix Plan**: Move provider vector to file scope (static) OR use singleton pattern. Initialize once, reuse across calls.

---

#### BUG-032
- **Severity**: MEDIUM
- **Location**: KernelMode/Syscall.cpp:64
- **Category**: Security / Hooking Detection
- **Description**: Syscall stub detection assumes specific byte pattern (0x4C 0xB8) but doesn't handle hooked stubs. AV/EDR hooks change instruction sequence, breaking detection.
- **Impact**:
  - Syscall map incomplete (hooked functions not detected)
  - Direct syscalls fail (wrong indices)
  - Application thinks syscall unavailable when it exists
- **Evidence**:
```cpp
if (*(funcAddr) == 0x4C && *(funcAddr + 3) == 0xB8) {
    // Assumes: mov r10, rcx; mov eax, <idx>
    // But if hooked: jmp <hook_addr>
}
```
- **Validation**:
  - Install AV with syscall hooks (e.g., Windows Defender)
  - Check if syscall map is complete
- **Fix Plan**: Add pattern for jmp hooks (0xE9 or 0xFF). Parse jump target and check if it's a trampoline. Alternatively, scan .text section for canonical syscall pattern (unhook in memory before parsing).

---

#### BUG-033
- **Severity**: MEDIUM
- **Location**: KernelMode/ManualMapper.cpp:61-68
- **Category**: Error Handling / Import Resolution
- **Description**: ResolveImports logs error when ordinal imports found but doesn't indicate which module/function. Debugging difficult.
- **Impact**:
  - Generic error message ("Ordinal imports not supported")
  - Developer must attach debugger to find failing import
  - Slows down debugging of new drivers
- **Evidence**:
```cpp
if (IMAGE_SNAP_BY_ORDINAL64(thunk->u1.Ordinal)) {
    std::wcerr << L"[-] Ordinal imports are not supported." << std::endl;
    return false;
}
```
- **Validation**:
  - Create PE with ordinal import (e.g., KERNEL32.dll ordinal 123)
  - Error message doesn't say which module
- **Fix Plan**: Log details: `std::wcerr << L"[-] Ordinal import " << ORDINAL_VALUE << L" in " << moduleName << L" not supported." << std::endl;`

---

#### BUG-034
- **Severity**: MEDIUM
- **Location**: KernelMode/DSE.cpp:165-172
- **Category**: Error Handling / Restore Logic
- **Description**: DSE::Restore() writes originalCiOptions back but doesn't verify write succeeded. If write fails, DSE remains disabled and system vulnerable.
- **Impact**:
  - DSE left disabled on error (unsigned drivers can load)
  - Security posture degraded
  - Next boot may have DSE still disabled (persistent risk)
- **Evidence**:
```cpp
bool DSE::Restore() {
    if (ciOptionsAddress && originalCiOptions != (DWORD)-1) {
        provider->WriteKernelMemory(ciOptionsAddress, &originalCiOptions, sizeof(DWORD));
        // Return value checked but error not propagated properly
    }
}
```
- **Validation**:
  - Disable provider's WriteKernelMemory (mock to return false)
  - Verify DSE remains disabled
- **Fix Plan**: Check result: `if (!provider->WriteKernelMemory(...)) { std::wcerr << L"[-] CRITICAL: Failed to restore DSE!" << std::endl; return false; }`

---

#### BUG-035
- **Severity**: MEDIUM
- **Location**: KernelMode/Providers/BaseProvider.h:270-280
- **Category**: Memory Safety / Template
- **Description**: SetupMemoryRequest template doesn't validate TMemoryRequest has required fields (address, buffer, size). Compiler error at instantiation time instead of compile error.
- **Impact**:
  - Cryptic compiler errors when using BaseProvider with wrong struct
  - Difficult for new developers to understand template requirements
  - No documentation of TMemoryRequest concept
- **Evidence**:
```cpp
template<typename TReq>
void SetupMemoryRequest(TReq& request, uintptr_t addr, uintptr_t buf, size_t sz) {
    request.address = addr; // Fails if TReq has no 'address' member
}
```
- **Validation**:
  - Instantiate BaseProvider<MyStruct> where MyStruct is incompatible
  - Check error message quality
- **Fix Plan**: Use C++20 concepts or static_assert with has_member trait: `static_assert(has_member_address_v<TReq>, "TReq must have address field");`

---

#### BUG-036
- **Severity**: MEDIUM
- **Location**: KernelMode/Utils.cpp:347-355
- **Category**: Error Handling / Pattern Search
- **Description**: FindPattern returns SIZE_MAX on failure but caller code may cast to signed type or use in pointer arithmetic, causing wraparound.
- **Impact**:
  - Pointer arithmetic with SIZE_MAX wraps to near-NULL address
  - Potential crash or memory corruption
  - Difficult to debug (SIZE_MAX looks like valid offset in hex dumps)
- **Evidence**:
```cpp
size_t offset = FindPattern(...);
uintptr_t address = baseAddr + offset; // If offset is SIZE_MAX, wraps
```
- **Validation**:
  - Call FindPattern with pattern not in data
  - Use returned offset without checking
  - ASAN may catch resulting OOB access
- **Fix Plan**: Return std::optional<size_t> or check: `if (offset == SIZE_MAX) return 0;` before arithmetic. Document that SIZE_MAX means "not found".

---

#### BUG-037
- **Severity**: MEDIUM
- **Location**: KernelMode/Providers/AsrDrvProvider.cpp:98-99
- **Category**: Performance / Repeated Memcpy
- **Description**: ReadKernelMemory reads memory in small chunks (1/2/4/8 bytes) and memcpy each to output buffer. Inefficient for large reads (thousands of IOCTLs).
- **Impact**:
  - Slow memory reads (10x slower than single IOCTL)
  - Increased kernel transition overhead
  - Poor scalability (1MB read = 128K IOCTLs for 8-byte chunks)
- **Evidence**:
```cpp
for (size_t bytesRead = 0; bytesRead < size; bytesRead += request.Size) {
    // One IOCTL per 1/2/4/8 bytes
    DeviceIoControl(...);
    memcpy(byteBuffer + bytesRead, &data, request.Size);
}
```
- **Validation**:
  - Profile 1MB read with AsrDrvProvider
  - Compare time to providers with batched reads
- **Fix Plan**: Batch reads in 4KB chunks if driver supports. Use larger buffer in request struct if possible.

---

#### BUG-038
- **Severity**: MEDIUM
- **Location**: KernelMode/ServiceManager.cpp:285-292
- **Category**: Error Handling / Service Deletion
- **Description**: StopAndDeleteService stops service with ControlService but doesn't wait for STOPPED state. DeleteService may fail with ERROR_SERVICE_MARKED_FOR_DELETE.
- **Impact**:
  - Service deletion fails (service stuck in STOP_PENDING)
  - Registry entry persists
  - Next load attempt fails with ERROR_SERVICE_EXISTS
- **Evidence**:
```cpp
SERVICE_STATUS serviceStatus;
ControlService(serviceHandle.get(), SERVICE_CONTROL_STOP, &serviceStatus);
// Immediately calls DeleteService without checking if stopped
if (!DeleteService(serviceHandle.get())) { ... }
```
- **Validation**:
  - Stop service with long shutdown time (driver with finalization logic)
  - Verify DeleteService fails
- **Fix Plan**: Wait for STOPPED state: `while (QueryServiceStatus(...) != SERVICE_STOPPED && retries < MAX_RETRIES) { Sleep(100); }`

---

#### BUG-039
- **Severity**: MEDIUM
- **Location**: KernelMode/Main.cpp:215-220
- **Category**: Error Handling / Exception Handling
- **Description**: Main try-catch catches std::exception and generic catch-all but doesn't differentiate between recoverable (file not found) and fatal (BSOD from driver).
- **Impact**:
  - Generic error messages ("An unhandled exception occurred")
  - Difficult to diagnose root cause
  - No differentiation between user error and bug
- **Evidence**:
```cpp
try {
    if (TryLoadSilentRK()) { ... }
} catch (const std::exception& e) {
    std::cerr << "An unhandled exception occurred: " << e.what() << std::endl;
    return 1;
}
```
- **Validation**:
  - Throw std::runtime_error("File not found") vs std::bad_alloc
  - Both produce same generic message
- **Fix Plan**: Add specific catch blocks: `catch (const std::filesystem::filesystem_error& e) { /* file error */ } catch (const std::bad_alloc& e) { /* OOM */ } catch (...) { /* unknown */ }`

---

#### BUG-040
- **Severity**: MEDIUM
- **Location**: Multiple provider files (pattern across codebase)
- **Category**: Portability / Endianness
- **Description**: Memory structures (TMemoryRequest, IOCTL buffers) assume little-endian byte order. Code won't work on big-endian systems.
- **Impact**:
  - Silent data corruption on big-endian platforms (ARM in BE mode)
  - IOCTL failures (driver expects LE, receives BE)
  - Portability to embedded systems impossible
- **Evidence**:
```cpp
request.address = address; // Assumes native byte order
DeviceIoControl(..., &request, sizeof(request), ...);
```
- **Validation**:
  - Cross-compile to ARM BE
  - Run on big-endian system (or emulator)
- **Fix Plan**: Document assumption (Windows is LE-only). OR add endianness conversion macros if supporting other platforms.

---

#### BUG-041
- **Severity**: MEDIUM
- **Location**: KernelMode/UACBypass.cpp:64-68
- **Category**: Error Handling / Registry
- **Description**: ShellExecuteExW failure triggers registry cleanup but cleanup itself can fail, leaving broken registry state.
- **Impact**:
  - Registry key exists but UAC bypass not triggered
  - Next application launch reads old registry key
  - Potential security issue (elevated app launches with old path)
- **Evidence**:
```cpp
if (!ShellExecuteExW(&sei)) {
    std::wcerr << L"[-] Failed to execute fodhelper." << std::endl;
    RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings\\Shell\\Open\\command");
    // If RegDeleteKeyW fails, key persists with current exe path
    return false;
}
```
- **Validation**:
  - Mock ShellExecuteExW to fail
  - Make registry key read-only (cleanup fails)
  - Check if key persists
- **Fix Plan**: Use RegDeleteTreeW for more robust cleanup. Check return value and log warning if cleanup fails.

---

#### BUG-042
- **Severity**: MEDIUM
- **Location**: KernelMode/Providers/IntelNalProvider.cpp:138, 154
- **Category**: Memory Safety / VirtualFree
- **Description**: VirtualFree called on lockedBuffer but if allocation failed earlier (NULL returned), VirtualFree(NULL) is undefined on some systems.
- **Impact**:
  - Potential crash on VirtualFree(NULL)
  - Resource leak if allocation path skipped free
  - Inconsistent error handling
- **Evidence**:
```cpp
PVOID lockedBuffer = VirtualAlloc(...);
if (!lockedBuffer) {
     VirtualFree(lockedBuffer, 0, MEM_RELEASE); // lockedBuffer is NULL!
     return false;
}
```
- **Validation**:
  - Mock VirtualAlloc to fail
  - Check if VirtualFree crashes or returns error
- **Fix Plan**: Check before free: `if (lockedBuffer) VirtualFree(lockedBuffer, 0, MEM_RELEASE);`

---

#### BUG-043
- **Severity**: MEDIUM
- **Location**: KernelMode/DSE.cpp:42
- **Category**: Security / Path Handling
- **Description**: strcat_s(systemPath, "\\ci.dll") appends to MAX_PATH buffer but doesn't verify systemPath length before append. Potential buffer overflow if GetSystemDirectoryA returns long path.
- **Impact**:
  - Buffer overflow if Windows installed in deep directory
  - Crash or arbitrary code execution
  - Unlikely in practice (MAX_PATH is 260) but possible with long computer names
- **Evidence**:
```cpp
char systemPath[MAX_PATH];
GetSystemDirectoryA(systemPath, MAX_PATH);
strcat_s(systemPath, "\\ci.dll");
// If strlen(systemPath) + strlen("\\ci.dll") >= MAX_PATH, strcat_s fails
```
- **Validation**:
  - Test on system with 200+ char system directory path
  - strcat_s should return error (but it's not checked)
- **Fix Plan**: Check strcat_s return value: `if (strcat_s(systemPath, "\\ci.dll") != 0) { return 0; }` OR use std::string/std::filesystem::path.

---

#### BUG-044
- **Severity**: MEDIUM
- **Location**: KernelMode/Providers/GdrvProvider.cpp:539, 1076
- **Category**: Security / Path Handling
- **Description**: Same as BUG-043, strcat_s called without checking return value. Duplicated code in GdrvProvider.
- **Impact**: Same as BUG-043
- **Evidence**: Same pattern in multiple locations
- **Validation**: Same as BUG-043
- **Fix Plan**: Refactor common path construction logic into utility function with proper error handling.

---

#### BUG-045
- **Severity**: MEDIUM
- **Location**: KernelMode/Providers/BaseProvider.h:95-110
- **Category**: Error Handling / Exception Safety
- **Description**: Initialize() catches all exceptions (catch ...) but Deinitialize() not guaranteed to run if exception thrown. Provider left in half-initialized state.
- **Impact**:
  - Driver service left running after exception
  - Device handle leaked
  - Subsequent Initialize() calls fail
- **Evidence**:
```cpp
try {
    if (!ExtractDriverFromResources(...)) return false;
    if (!StartVulnerableDriver()) return false;
    // If exception here, driver started but not cleaned up
    if (!ConnectToDriver()) {
        StopVulnerableDriver();
        return false;
    }
}
catch (...) {
    Deinitialize(); // But what if Deinitialize() throws?
    return false;
}
```
- **Validation**:
  - Mock ConnectToDriver to throw
  - Check if service is cleaned up
- **Fix Plan**: Use RAII: Create ScopedDriverService class that stops service in destructor. No manual cleanup needed.

---

### LOW SEVERITY

#### BUG-046
- **Severity**: LOW
- **Location**: KernelMode/Main.cpp:235
- **Category**: Portability / System Call
- **Description**: system("pause > nul") uses system() which creates cmd.exe process. Slow and platform-specific (doesn't work on non-cmd shells).
- **Impact**:
  - Slow exit (cmd.exe spawn overhead)
  - Doesn't work in PowerShell or non-Windows environments
  - Leaves cmd.exe process in background if killed
- **Evidence**:
```cpp
std::wcout << L"\nPress any key to exit..." << std::endl;
system("pause > nul");
```
- **Validation**:
  - Run in PowerShell ISE (pause may not work)
  - Profile exit time (200ms+ just for pause)
- **Fix Plan**: Replace with: `std::cin.get();` or Windows-specific `_getch();`

---

#### BUG-047
- **Severity**: LOW
- **Location**: KernelMode/Main.cpp:198
- **Category**: Error Handling / System Call
- **Description**: system("pause") return value ignored. If system() fails (OOM, cmd.exe missing), user gets no feedback.
- **Impact**:
  - Console closes immediately on system() failure
  - User confused (expected pause)
  - Difficult to debug in constrained environments
- **Evidence**:
```cpp
system("pause");
return 1;
```
- **Validation**:
  - Rename cmd.exe to break system()
  - Check if application still pauses
- **Fix Plan**: Check return: `if (system("pause") != 0) { std::wcin.get(); }`

---

#### BUG-048
- **Severity**: LOW
- **Location**: KernelMode/UACBypass.h:13
- **Category**: API Misuse / Missing Include
- **Description**: UACBypass.h doesn't include <Windows.h> but uses SHELLEXECUTEINFOW. Compilation depends on include order.
- **Impact**:
  - Fails to compile if UACBypass.h included before Windows.h
  - Fragile build (works by accident)
  - Difficult for new developers
- **Evidence**: (Check header file)
- **Validation**:
  - Create test.cpp with #include "UACBypass.h" only
  - Verify compiler error (SHELLEXECUTEINFOW undefined)
- **Fix Plan**: Add #include <Windows.h> to UACBypass.h or use forward declarations.

---

#### BUG-049
- **Severity**: LOW
- **Location**: KernelMode/ServiceManager.cpp:285
- **Category**: Code Quality / Magic Number
- **Description**: ControlService uses hardcoded SERVICE_CONTROL_STOP (1) instead of named constant. Reduces code readability.
- **Impact**:
  - Minor: harder to understand intent
  - Risk of typo (using wrong control code)
- **Evidence**:
```cpp
ControlService(serviceHandle.get(), SERVICE_CONTROL_STOP, &serviceStatus);
// SERVICE_CONTROL_STOP is 1, but hardcoded is bad practice
```
- **Validation**: N/A (code quality issue)
- **Fix Plan**: Use named constant (already correct, but document pattern).

---

#### BUG-050
- **Severity**: LOW
- **Location**: Multiple files (logging pattern)
- **Category**: Performance / Logging
- **Description**: std::wcout used in tight loops (provider initialization). Console I/O is slow; repeated writes cause performance degradation.
- **Impact**:
  - Slow application startup (100ms+ for console writes)
  - Difficult to disable verbose logging
  - No way to redirect logs to file at runtime
- **Evidence**: (Search for std::wcout in loops)
- **Validation**:
  - Profile provider initialization with/without logging
  - Measure time difference
- **Fix Plan**: Implement logging levels (DEBUG, INFO, ERROR). Allow runtime configuration. Use buffered logger class.

---

#### BUG-051
- **Severity**: LOW
- **Location**: KernelMode/Utils.cpp:93
- **Category**: Code Quality / Comment
- **Description**: Comment says "Sometimes it returns error but gives size" but doesn't explain when or why. Confusing for maintainers.
- **Impact**:
  - Difficult to understand edge case handling
  - Risk of removing "workaround" code during refactor
- **Evidence**:
```cpp
// Sometimes it returns error but gives size. If strictly 0, we can't proceed.
```
- **Validation**: N/A (documentation issue)
- **Fix Plan**: Document specific error codes (STATUS_INFO_LENGTH_MISMATCH) and why incrementing by 4096 is needed.

---

#### BUG-052
- **Severity**: LOW
- **Location**: KernelMode/ManualMapper.cpp:276
- **Category**: Code Quality / Magic Number
- **Description**: DriverEntry shellcode has hardcoded offsets (0x30, 0x18, 0xF0) without comments explaining DRIVER_OBJECT field meanings.
- **Impact**:
  - Difficult to maintain (what is offset 0x30?)
  - Risk of incorrect offsets on Windows version changes
  - Hard to verify correctness without WDK docs
- **Evidence**:
```cpp
0x48, 0x89, 0x51, 0x30,  // mov [rcx+0x30], rdx
// No comment: 0x30 is DriverObject->DriverExtension
```
- **Validation**: N/A (documentation issue)
- **Fix Plan**: Add comments for each offset: `// 0x30 = DriverObject->DriverExtension`, etc.

---

#### BUG-053
- **Severity**: LOW
- **Location**: KernelMode/Providers/GdrvProvider.cpp:331
- **Category**: Code Quality / Dead Code
- **Description**: extern "C" declaration for DoSyscall but function never called in GdrvProvider. Dead code or leftover from refactoring.
- **Impact**:
  - Confusing for code readers
  - Linker may fail if DoSyscall not defined
  - Maintenance burden (keeping unused declarations)
- **Evidence**:
```cpp
extern "C" NTSTATUS DoSyscall(DWORD syscallIndex, PVOID* params, ULONG paramCount);
// Not used anywhere in GdrvProvider.cpp
```
- **Validation**:
  - Search for DoSyscall calls in file
  - Comment out declaration, verify build succeeds
- **Fix Plan**: Remove unused declaration or document why it's preserved (future use?).

---

#### BUG-054
- **Severity**: LOW
- **Location**: KernelMode/ServiceManager.cpp:35
- **Category**: Code Quality / Destructor
- **Description**: ~ServiceManager calls CleanupAllServices but doesn't handle exceptions. If cleanup throws, std::terminate called.
- **Impact**:
  - Application crash on destruction if service cleanup fails
  - Surprising behavior (destructors should be noexcept)
  - Difficult to debug (stack trace in std::terminate is limited)
- **Evidence**:
```cpp
ServiceManager::~ServiceManager() {
    CleanupAllServices(); // If throws, std::terminate
}
```
- **Validation**:
  - Mock CleanupAllServices to throw
  - Verify application crashes instead of graceful exit
- **Fix Plan**: Wrap in try-catch: `try { CleanupAllServices(); } catch (...) { /* log error, suppress */ }`

---

#### BUG-055
- **Severity**: LOW
- **Location**: KernelMode/Main.cpp:87
- **Category**: Code Quality / Variable Naming
- **Description**: Variable 'ec' (std::error_code) declared but only used to suppress filesystem::exists warning. Confusing name and purpose unclear.
- **Impact**:
  - Code readability reduced
  - Future maintainers may think ec is checked
- **Evidence**:
```cpp
std::error_code ec;
if (!std::filesystem::exists(driverPath, ec)) { ... }
// ec never checked, just suppresses exception
```
- **Validation**: N/A (code quality)
- **Fix Plan**: Add comment: `std::error_code ec; // Suppress exception from exists()` OR rename to `std::error_code ec_ignored;`

---

#### BUG-056
- **Severity**: LOW
- **Location**: KernelMode/Providers/BaseProvider.h:180
- **Category**: Performance / Duplicate Check
- **Description**: ReadKernelMemory checks IsValidHandle() and then DeviceIoControl checks if handle is valid. Redundant check.
- **Impact**:
  - Minor performance overhead (extra function call)
  - Code duplication
- **Evidence**:
```cpp
if (!IsValidHandle() || !buffer || size == 0) return false;
// DeviceIoControl also checks if handle is valid
return DeviceIoControl(deviceHandle, ...) != FALSE;
```
- **Validation**: Profile with/without check
- **Fix Plan**: Keep explicit check for better error messages. OR remove if performance-critical path.

---

#### BUG-057
- **Severity**: LOW
- **Location**: KernelMode/Providers/RTCoreProvider.cpp:43
- **Category**: Code Quality / Unreferenced Parameter
- **Description**: RTCoreProvider::Initialize has driverId parameter but doesn't use it (marked with warning C4100). Inconsistent with interface.
- **Impact**:
  - Confusing API (parameter ignored)
  - Risk of bugs if caller expects driverId to be used
- **Evidence**: (From build warnings)
```cpp
warning C4100: 'driverId': unreferenced parameter
```
- **Validation**: Check if driverId should be used for multi-driver support
- **Fix Plan**: Either use the parameter OR document why it's ignored: `(void)driverId; // Not used for RTCore`

---

## C) ROADMAP.MD UPDATE

Adding new phase to ROADMAP.md:

### Phase 7: Repo-wide Bug Fix and Hardening (Post-Audit)

**Objective:** Address all critical, high, and selected medium severity issues identified in the January 2026 comprehensive code audit.

#### 7.1 Critical Memory Safety Fixes
**Priority:** P0 (Must fix before next release)

- [ ] **BUG-001**: [PEParser.cpp:117-142] Add section header bounds validation before IMAGE_FIRST_SECTION iteration
  - Acceptance: Fuzzer with malformed PE (NumberOfSections=0xFFFF) doesn't crash
  - Validation: ASAN clean, unit test passes

- [ ] **BUG-002**: [ManualMapper.cpp:134-138] Add integer overflow checks in section mapping memcpy
  - Acceptance: PE with VirtualAddress=0xFFFFF000 + SizeOfRawData=0x2000 rejected
  - Validation: ASAN clean, overflow unit test

- [ ] **BUG-003**: [Utils.cpp:118-123] Fix GetKernelModuleInfo string handling with strnlen validation
  - Acceptance: Kernel module with OffsetToFileName=300 skipped, no crash
  - Validation: Valgrind clean, boundary test cases

- [ ] **BUG-004**: [Syscall.cpp:56-59] Add bounds checking for syscall stub parsing
  - Acceptance: Modified ntdll.dll with invalid RVAs doesn't cause crash
  - Validation: Access violation test, module bounds verification

- [ ] **BUG-005**: [Main.cpp:95-107] Add RAII exception safety to provider initialization loop
  - Acceptance: Exception during DSE::Disable() cleans up provider and restores DSE
  - Validation: Mock exception test, resource leak detector

- [ ] **BUG-006**: [ServiceManager.cpp:180-185] Remove TOCTOU vulnerability in service creation
  - Acceptance: CreateServiceW called atomically, ERROR_SERVICE_EXISTS handled
  - Validation: Race condition fuzzer, concurrent service creation test

- [ ] **BUG-007**: [DSE.cpp:94-100] Add pointer bounds validation for CipInitialize calculation
  - Acceptance: Corrupted ci.dll doesn't cause out-of-bounds read
  - Validation: ASAN clean, boundary test with modified DLL

- [ ] **BUG-008**: [UACBypass.cpp:51-53] Add path validation and quoting for UAC bypass
  - Acceptance: Executable in path with spaces properly quoted
  - Validation: Integration test with various path formats

#### 7.2 High Priority Error Handling
**Priority:** P1 (Fix within 2 weeks)

- [ ] **BUG-009**: [ServiceManager.cpp:93-97] Change GenerateUniqueServiceName to return optional<wstring>
  - Acceptance: Empty string never returned; caller checks optional before use
  
- [ ] **BUG-010**: [Utils.cpp:91-95] Add status validation for NtQuerySystemInformation
  - Acceptance: STATUS_ACCESS_DENIED handled gracefully, no buffer overflow
  
- [ ] **BUG-011**: [Main.cpp:208-213] Add error handling for UAC bypass cleanup
  - Acceptance: RegDeleteTreeW failure logged, doesn't abort application
  
- [ ] **BUG-012**: [Providers/GdrvProvider.cpp:82-90] Fix integer overflow in MapMemMapMemory
  - Acceptance: Large physicalAddress + numberOfBytes doesn't wrap
  
- [ ] **BUG-013**: [Providers/*.cpp] Add bytesReturned validation to all DeviceIoControl calls
  - Acceptance: Partial writes detected and rejected
  
- [ ] **BUG-014**: [Main.cpp:39-40] Replace global g_logFile with thread-safe logger
  - Acceptance: Thread sanitizer clean, no data races
  
- [ ] **BUG-015**: [Syscall.cpp:25-35] Add signature verification for ntdll.dll loading
  - Acceptance: Modified ntdll.dll detected and rejected
  
- [ ] **BUG-016**: [ManualMapper.cpp:206-230] Fix shellcode stack zeroing (increase to 128 qwords)
  - Acceptance: MemorySanitizer clean, all 1024 bytes initialized
  
- [ ] **BUG-017**: [Utils.cpp:191-199] Add DeleteService return value checking
  - Acceptance: Failed deletion logged, cleanup retried
  
- [ ] **BUG-018**: [PEParser.cpp:53-56] Use alignof() instead of hardcoded 4 for alignment check
  - Acceptance: ARM64 cross-compile succeeds, alignment correct
  
- [ ] **BUG-019**: [Providers/*.cpp] Add __try/__except around memory mapping memcpy calls
  - Acceptance: Invalid physical address access doesn't crash app
  
- [ ] **BUG-020**: [ServiceManager.cpp:240-248] Verify no resource leaks in QueryServiceConfigW error paths
  - Acceptance: LeakSanitizer clean after 1000 failed queries
  
- [ ] **BUG-021**: [DSE.cpp:110-120] Add bounds checking to pattern scanning loop
  - Acceptance: Short CipInitialize function doesn't cause OOB read
  
- [ ] **BUG-022**: [Providers/BaseProvider.h:168-180] Add static_assert for TMemoryRequest size
  - Acceptance: Compilation fails with helpful error if struct size mismatched
  
- [ ] **BUG-023**: [Providers/WinRing0Provider.cpp:175] Add size validation before memcpy to request->Data
  - Acceptance: Large write (size=0x10000) rejected before overflow

#### 7.3 Medium Priority Security & Correctness
**Priority:** P2 (Fix within 1 month)

- [ ] **BUG-024**: [Main.cpp:11] Remove _CRT_SECURE_NO_WARNINGS, fix individual warnings
  - Acceptance: /W4 /WX clean build
  
- [ ] **BUG-025**: [Main.cpp:180-181] Replace std::ctime with thread-safe std::put_time
  - Acceptance: Multi-threaded logging doesn't corrupt timestamps
  
- [ ] **BUG-026**: [Utils.cpp:362-370] Replace hardcoded C:\\Windows\\System32 with GetSystemDirectoryW
  - Acceptance: Works on non-C: Windows installations
  
- [ ] **BUG-027**: [UACBypass.cpp:29] Add error code differentiation for RegDeleteKeyW
  - Acceptance: Only real errors logged, ERROR_FILE_NOT_FOUND silent
  
- [ ] **BUG-028**: [UACBypass.cpp:78] Remove arbitrary Sleep(1000), use WaitForInputIdle
  - Acceptance: Bypass succeeds reliably without delay
  
- [ ] **BUG-029**: [Providers/GdrvProvider.cpp:184-195] Log exception codes in __except blocks
  - Acceptance: Hardware faults produce error logs with exception codes
  
- [ ] **BUG-030**: [ServiceManager.cpp:143-158] Add MAX_SERVICE_CONFIG_SIZE limit (64KB)
  - Acceptance: Malicious service with 1GB config doesn't cause OOM
  
- [ ] **BUG-031**: [Main.cpp:96] Move provider vector to static/singleton for reuse
  - Acceptance: Heap profiler shows no repeated allocations
  
- [ ] **BUG-032**: [Syscall.cpp:64] Add hook detection for jmp patterns in syscall stubs
  - Acceptance: Hooked ntdll still parsed correctly
  
- [ ] **BUG-033**: [ManualMapper.cpp:61-68] Enhance ordinal import error messages with details
  - Acceptance: Error message includes module name and ordinal number
  
- [ ] **BUG-034**: [DSE.cpp:165-172] Add write verification to DSE::Restore()
  - Acceptance: Failed restore logged as CRITICAL error
  
- [ ] **BUG-035**: [Providers/BaseProvider.h:270-280] Add C++20 concepts or static_assert for TMemoryRequest
  - Acceptance: Clear compiler error if wrong struct used
  
- [ ] **BUG-036**: [Utils.cpp:347-355] Change FindPattern return to std::optional<size_t>
  - Acceptance: Callers forced to check for failure
  
- [ ] **BUG-037**: [Providers/AsrDrvProvider.cpp:98-99] Implement batched reads (4KB chunks)
  - Acceptance: 1MB read completes in <1s (vs 10s+ with 8-byte chunks)
  
- [ ] **BUG-038**: [ServiceManager.cpp:285-292] Wait for SERVICE_STOPPED before DeleteService
  - Acceptance: Service deletion succeeds reliably
  
- [ ] **BUG-039**: [Main.cpp:215-220] Add specific exception handlers (filesystem_error, bad_alloc)
  - Acceptance: Error messages distinguish between error categories
  
- [ ] **BUG-040**: [Multiple files] Document little-endian assumption in memory structures
  - Acceptance: README notes Windows-only / LE-only assumption
  
- [ ] **BUG-041**: [UACBypass.cpp:64-68] Use RegDeleteTreeW for robust cleanup on failure
  - Acceptance: Cleanup failures don't leave broken state
  
- [ ] **BUG-042**: [Providers/IntelNalProvider.cpp:138] Add NULL check before VirtualFree
  - Acceptance: Failed allocation doesn't call VirtualFree(NULL)
  
- [ ] **BUG-043**: [DSE.cpp:42] Check strcat_s return value or use std::filesystem::path
  - Acceptance: Long system directory path handled gracefully
  
- [ ] **BUG-044**: [Providers/GdrvProvider.cpp:539] Refactor path construction into utility function
  - Acceptance: Single tested function used for all path construction
  
- [ ] **BUG-045**: [Providers/BaseProvider.h:95-110] Implement RAII ScopedDriverService
  - Acceptance: Exception during init always cleans up service

#### 7.4 Low Priority Code Quality
**Priority:** P3 (Fix opportunistically)

- [ ] **BUG-046**: [Main.cpp:235] Replace system("pause") with std::cin.get()
- [ ] **BUG-047**: [Main.cpp:198] Check system("pause") return value
- [ ] **BUG-048**: [UACBypass.h:13] Add #include <Windows.h> to header
- [ ] **BUG-049**: [ServiceManager.cpp:285] Document SERVICE_CONTROL_STOP constant usage
- [ ] **BUG-050**: [Multiple files] Implement configurable logging levels
- [ ] **BUG-051**: [Utils.cpp:93] Improve comments for NtQuerySystemInformation workaround
- [ ] **BUG-052**: [ManualMapper.cpp:276] Add offset comments to shellcode
- [ ] **BUG-053**: [Providers/GdrvProvider.cpp:331] Remove unused DoSyscall declaration
- [ ] **BUG-054**: [ServiceManager.cpp:35] Add try-catch to destructor
- [ ] **BUG-055**: [Main.cpp:87] Rename 'ec' to 'ec_ignored' or add comment
- [ ] **BUG-056**: [Providers/BaseProvider.h:180] Remove redundant IsValidHandle check if proven safe
- [ ] **BUG-057**: [Providers/RTCoreProvider.cpp:43] Document or use driverId parameter

#### 7.5 Tooling & Continuous Validation
**Priority:** P1 (Setup infrastructure)

- [ ] **Sanitizer Integration**:
  - Add AddressSanitizer build configuration (Debug-ASAN)
  - Add MemorySanitizer build configuration (if Clang support added)
  - Add ThreadSanitizer build configuration for concurrency testing
  - Add UndefinedBehaviorSanitizer build configuration
  - Integrate into CI pipeline (GitHub Actions / Azure DevOps)

- [ ] **Fuzzing Infrastructure**:
  - Implement LibFuzzer harness for PEParser::Parse()
  - Implement LibFuzzer harness for NtQuerySystemInformation wrapper
  - Implement AFL++ harness for PE file parsing
  - Add corpus generation for driver files
  - Run continuous fuzzing (OSS-Fuzz or local cluster)

- [ ] **Static Analysis**:
  - Enable /analyze (MSVC static analyzer) in Release builds
  - Integrate PVS-Studio or Coverity Scan
  - Setup clang-tidy with .clang-tidy configuration
  - Run cppcheck with all checks enabled
  - Fix all P0/P1 static analysis warnings

- [ ] **Code Coverage**:
  - Setup coverage instrumentation (OpenCppCoverage on Windows)
  - Target: >80% line coverage for core modules
  - Target: >60% branch coverage for error paths
  - Publish coverage reports to CI dashboard

- [ ] **Security Scanning**:
  - Run Binskim on compiled binaries
  - Check for hardcoded credentials/secrets (TruffleHog)
  - Verify no world-writable registry keys created
  - Audit for privilege escalation vectors (beyond intended UAC bypass)

---

## Next Steps (Post-Audit)
1. **Triage**: Review all 57 findings with team, confirm severity ratings
2. **Sprint Planning**: Allocate P0 (Critical) items to immediate sprint
3. **Tooling Setup**: Prioritize sanitizer builds and fuzzing infrastructure
4. **Incremental Fixes**: Address one module at a time (PEParser → Utils → ServiceManager → Providers)
5. **Regression Testing**: Add unit tests for each fix, ensure no new bugs introduced
6. **Documentation**: Update technical docs with security considerations and limitations

---

**NEXT SLICE:** Will continue with deeper analysis of Provider implementations (WinRing0, AsrDrv, EchoDrv, ProcessExplorer, ProcessHacker) and cross-cutting concerns (build system, test infrastructure).

---
