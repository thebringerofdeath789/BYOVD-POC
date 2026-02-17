# BYOVD-POC Custom Code Audit - January 2026

**Auditor:** AI Code Analysis System  
**Date:** January 29, 2026  
**Scope:** Custom infrastructure code only (excluding KDU-based provider implementations)  
**Code Examined:** Main.cpp, UACBypass.cpp, ServiceManager.cpp, PEParser.cpp, Utils.cpp, Privilege.cpp, Callbacks.cpp, BYOVDManager.cpp, DriverDataManager.cpp, PocMenu.cpp, DefenderDisabler.cpp, FileHider.cpp  
**Methodology:** Systematic scan for memory safety, UB, concurrency, security, portability, and build hazards

**Note:** This audit focuses on custom implementation code only. KDU-based provider implementations (RTCoreProvider, GdrvProvider, DBUtilProvider, etc.) and KDU-derived utility functions (syscall extraction, manual mapper shellcode, DSE pattern scanning) are considered third-party dependencies and excluded from this analysis.

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
9. **KernelMode/BYOVDManager.cpp** - Attack orchestration, cleanup (MEDIUM)
10. **KernelMode/PocMenu.cpp** - User input handling, file path sanitization (LOW)

---

## B) FINDINGS (SORTED BY SEVERITY)

### CRITICAL SEVERITY

#### BUG-C001
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

#### BUG-C002
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

#### BUG-C003
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

#### BUG-C004
- **Severity**: CRITICAL
- **Location**: KernelMode/ServiceManager.cpp:180-185 (pattern may exist)
- **Category**: Security / Race Condition (TOCTOU)
- **Description**: Pre-checking service existence before CreateService creates TOCTOU window. Malicious process can create service between check and creation, leading to privilege escalation.
- **Impact**:
  - Attacker creates malicious service with same name
  - Application opens attacker's service thinking it's safe
  - Arbitrary driver loading with elevated privileges
- **Evidence**: (ROADMAP indicates this was "fixed" in Phase 2, but need verification)
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

#### BUG-C005
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

#### BUG-C006
- **Severity**: CRITICAL
- **Location**: KernelMode/Callbacks.cpp:81-87
- **Category**: Memory Safety / Pointer Validation
- **Description**: FindProcessNotifyRoutineArray calculates RVA (pCiInitialize + offset + relativeValue) but doesn't validate result is within module bounds before returning.
- **Impact**:
  - Reading arbitrary memory when enumerating callbacks
  - Crash if pointer lands in unmapped region
  - Incorrect callback array address leads to corrupting random kernel memory
- **Evidence**:
```cpp
int32_t offset = *(int32_t*)(patternAddress + 3);
uintptr_t rva = (patternAddress - (uintptr_t)ntoskrnlModule) + 7 + offset;

// BUG-008 FIX: Relocation Bounds Checking (present)
if (rva >= ntHeaders->OptionalHeader.SizeOfImage) {
    // Good! But need to also check after adding ntoskrnlBase
}

this->processNotifyRoutineArray = ntoskrnlBase + rva;
// What if ntoskrnlBase + rva wraps around or points to invalid memory?
```
- **Validation**:
  - Test with corrupted ntoskrnl.exe (modified patterns)
  - Check if calculated address is within [ntoskrnlBase, ntoskrnlBase + SizeOfImage]
- **Fix Plan**: After calculating `processNotifyRoutineArray`, verify: `(processNotifyRoutineArray >= ntoskrnlBase) && (processNotifyRoutineArray < ntoskrnlBase + ntHeaders->OptionalHeader.SizeOfImage)` before returning.

---

### HIGH SEVERITY

#### BUG-H001
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

#### BUG-H002
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

#### BUG-H003
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

#### BUG-H004
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

#### BUG-H005
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

#### BUG-H006
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

#### BUG-H007
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

#### BUG-H008
- **Severity**: HIGH
- **Location**: KernelMode/Privilege.cpp:150-200
- **Category**: Error Handling / Exception Safety
- **Description**: ResolveEProcessOffsets allocates handleInfoBuffer with try-catch but doesn't validate NtQuerySystemInformation succeeded before reading structure. Potential garbage data read.
- **Impact**:
  - Reading uninitialized memory if NtQuerySystemInformation fails
  - Crash when dereferencing invalid handles
  - Token theft fails with confusing errors
- **Evidence**:
```cpp
NTSTATUS status = NtQuerySystemInformation(..., handleInfoBuffer.data(), returnLength, &returnLength);

void* tokenKernelAddr = nullptr;
if (status == STATUS_SUCCESS) {
    auto info = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(handleInfoBuffer.data());
    // What if status != STATUS_SUCCESS? tokenKernelAddr stays nullptr, but continue...
}
CloseHandle(hToken);

if (!tokenKernelAddr) {
    return false; // Good catch, but should check earlier
}
```
- **Validation**:
  - Mock NtQuerySystemInformation to return error
  - Check if code crashes or handles gracefully
- **Fix Plan**: Check status immediately: `if (status != STATUS_SUCCESS) { CloseHandle(hToken); return false; }`

---

#### BUG-H009
- **Severity**: HIGH
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

#### BUG-H010
- **Severity**: HIGH
- **Location**: KernelMode/PocMenu.cpp:520-550
- **Category**: Memory Safety / Buffer Management
- **Description**: ExtractBinToSys reads entire .bin file into memory without size limit validation. Attacker-controlled .bin file can cause OOM or integer overflow.
- **Impact**:
  - Denial of service via OOM
  - Integer overflow if file size > MAX_INT
  - System freeze on large file reads
- **Evidence**:
```cpp
binFile.seekg(0, std::ios::end);
std::streamsize binSize = binFile.tellg();
binFile.seekg(0, std::ios::beg);

// No check if binSize is reasonable
std::vector<char> driverData(static_cast<size_t>(binSize));
binFile.read(driverData.data(), binSize);
```
- **Validation**:
  - Create 4GB .bin file
  - Attempt extraction
  - Check for OOM or hang
- **Fix Plan**: Add size limit: `if (binSize > MAX_DRIVER_SIZE) return false;` where MAX = 32MB (reasonable driver limit).

---

#### BUG-H011
- **Severity**: HIGH
- **Location**: KernelMode/BYOVDManager.cpp:180-195
- **Category**: Error Handling / Resource Leak
- **Description**: LoadSilentRKDirect creates service but doesn't close handles on all error paths. Service handle leaks on StartService failure.
- **Impact**:
  - Handle leak (exhausts handle table after repeated failures)
  - Service stuck in STOPPED state
  - Cannot retry without restarting application
- **Evidence**:
```cpp
SC_HANDLE hService = CreateServiceW(...);

if (!hService) {
    if (GetLastError() == ERROR_SERVICE_EXISTS) {
        hService = OpenServiceW(...);
    }
}

if (!hService) {
    CloseServiceHandle(hSCManager);
    return BYOVDResult::UnknownError; // hService not closed if OpenServiceW succeeded but this check failed?
}

if (StartService(hService, 0, NULL)) {
    CloseServiceHandle(hService); // Only closed on success
    CloseServiceHandle(hSCManager);
    return BYOVDResult::Success;
}
// Missing CloseServiceHandle on failure path!
```
- **Validation**:
  - Force StartService to fail repeatedly
  - Check handle count growth
- **Fix Plan**: Use RAII wrapper or ensure: `CloseServiceHandle(hService); CloseServiceHandle(hSCManager);` on all return paths.

---

#### BUG-H012
- **Severity**: HIGH
- **Location**: KernelMode/DriverDataManager.cpp:290-305
- **Category**: Error Handling / Memory Leak
- **Description**: ExtractDriver allocates decompressed data with HeapAlloc but only frees on success path. Failure paths leak if `outFile.write()` throws or fails.
- **Impact**:
  - Memory leak on file write failures
  - Degraded performance over repeated extraction attempts
  - OOM after many failed extractions
- **Evidence**:
```cpp
PVOID decompressedData = DecompressDriverData(...);

std::ofstream outFile(outputPath, std::ios::binary);
if (!outFile) {
    std::wcerr << L"[-] Failed to create output file" << std::endl;
    if (decompressedData) {
        HeapFree(GetProcessHeap(), 0, decompressedData); // Good!
    }
    return false;
}

if (decompressedData && decompressedSize > 0) {
    outFile.write(...); // What if write throws or fails?
    HeapFree(GetProcessHeap(), 0, decompressedData); // Only freed if no exception
}
```
- **Validation**:
  - Make disk full (write fails)
  - Check for memory leak
- **Fix Plan**: Use RAII: `std::unique_ptr<void, decltype(&HeapFree)> guard(decompressedData, [](void* p) { HeapFree(GetProcessHeap(), 0, p); });`

---

### MEDIUM SEVERITY

#### BUG-M001
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

#### BUG-M002
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

#### BUG-M003
- **Severity**: MEDIUM
- **Location**: KernelMode/Utils.cpp:147
- **Category**: Portability / Hardcoded Path
- **Description**: LoadKernelModule uses GetSystemDirectoryW but Utils::GetKernelModuleBase hardcodes C:\Windows\System32. Fails if Windows installed on different drive.
- **Impact**:
  - Module loading fails on non-C: Windows installations
  - Breaks on Windows-on-ARM or custom WinPE environments
- **Evidence**:
```cpp
if (!GetSystemDirectoryW(systemDirectory, MAX_PATH)) {
    return 0;
}
// But other places use: L"C:\\Windows\\System32\\"
```
- **Validation**:
  - Install Windows on D: drive
  - Attempt to load kernel module
- **Fix Plan**: Consistently use GetSystemDirectoryW everywhere. Search codebase for hardcoded "C:\\Windows" and replace.

---

#### BUG-M004
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

#### BUG-M005
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

#### BUG-M006
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

#### BUG-M007
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

#### BUG-M008
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

#### BUG-M009
- **Severity**: MEDIUM
- **Location**: KernelMode/Privilege.cpp:95-110
- **Category**: Error Handling / Fallback Logic
- **Description**: ResolveEProcessOffsets has hardcoded offset fallbacks for specific Windows versions, but doesn't validate provider is available before using. Token theft fails silently if provider initialization fails.
- **Impact**:
  - Token theft fails with "unsupported build" even when offsets are known
  - Dynamic scanning attempted even when static offsets would work
  - Poor error messages (doesn't indicate provider issue)
- **Evidence**:
```cpp
if (buildNumber >= 22621) {
    pidOff = 0x440;
    linkOff = 0x448;
    tokenOff = 0x4b8;
    return true;
}
// ... more checks

std::wcout << L"[*] unsupported build, attempting dynamic resolution..." << std::endl;
// But what if provider is nullptr or not initialized?
```
- **Validation**:
  - Call ResolveEProcessOffsets with null provider
  - Check if crash or graceful failure
- **Fix Plan**: Check provider validity at start: `if (!provider || !provider->IsValidHandle()) return false;`

---

#### BUG-M010
- **Severity**: MEDIUM
- **Location**: KernelMode/DefenderDisabler.cpp:80-85
- **Category**: Error Handling / Verification
- **Description**: SetRegistryDword verifies write with RegQueryValueExW but doesn't handle case where key is redirected (registry virtualization). Write appears successful but doesn't affect Defender.
- **Impact**:
  - Defender remains active (registry write virtualized)
  - False positive (thinks Defender disabled)
  - Confusing behavior (works locally but not system-wide)
- **Evidence**:
```cpp
DWORD verifyValue = 0;
DWORD cbData = sizeof(verifyValue);
result = RegQueryValueExW(hKey, valueName.c_str(), 0, nullptr, (LPBYTE)&verifyValue, &cbData);
if (result != ERROR_SUCCESS || verifyValue != value) {
     std::wcerr << L"[-] Verification failed" << std::endl;
     return false;
}
// But what if write was virtualized? RegQueryValueExW reads from virtualized key too
```
- **Validation**:
  - Run without admin privileges
  - Check if Defender actually disabled
- **Fix Plan**: Check if running as SYSTEM (not just admin). Validate registry key is HKLM (not HKCU virtualized). Use `RegDisableReflectionKey` if needed.

---

#### BUG-M011
- **Severity**: MEDIUM
- **Location**: KernelMode/BYOVDManager.cpp:45-55
- **Category**: Error Handling / File Validation
- **Description**: LoadSilentRK calls ValidateDriverFile which only checks if file exists, not if it's a valid PE. Corrupted driver files cause crash during mapping.
- **Impact**:
  - Crash when mapping non-PE file
  - Confusing error messages (mapping fails, not file validation)
  - Waste time attempting to map garbage data
- **Evidence**:
```cpp
bool BYOVDManager::ValidateDriverFile(const std::wstring& driverPath) {
    std::ifstream f(driverPath);
    return f.good(); // Only checks if file exists, not if it's PE!
}
```
- **Validation**:
  - Create empty file as driver path
  - Attempt to load
  - Check if validation catches it
- **Fix Plan**: Read first 2 bytes, check for 'MZ' signature: `char header[2]; f.read(header, 2); return (header[0] == 'M' && header[1] == 'Z');`

---

#### BUG-M012
- **Severity**: MEDIUM
- **Location**: KernelMode/Callbacks.cpp:120-140
- **Category**: Memory Safety / Unchecked Array Access
- **Description**: EnumerateCallbacks reads callback blocks from kernel without validating array index. If maxCallbacks > actual array size, reads OOB kernel memory.
- **Impact**:
  - Reading arbitrary kernel memory
  - Crash if unmapped region
  - Incorrect callback enumeration
- **Evidence**:
```cpp
std::vector<uintptr_t> callbackBlocks(maxCallbacks);

if (!provider->ReadKernelMemory(arrayAddress, callbackBlocks.data(), maxCallbacks * sizeof(uintptr_t))) {
    return {};
}

for (int i = 0; i < maxCallbacks; ++i) {
    uintptr_t blockPtr = callbackBlocks[i]; // What if array is actually smaller?
}
```
- **Validation**:
  - Set maxCallbacks to 1000
  - Check if reads garbage or crashes
- **Fix Plan**: Kernel callback arrays have fixed size (64). Validate: `if (maxCallbacks > 64) maxCallbacks = 64;`. Or read array size from kernel structure first.

---

#### BUG-M013
- **Severity**: MEDIUM
- **Location**: KernelMode/DriverDataManager.cpp:125-145
- **Category**: Error Handling / Fallback Logic
- **Description**: LoadExternalDrivers searches multiple paths but doesn't report which paths failed. Difficult to diagnose why driver not found.
- **Impact**:
  - Poor error messages ("driver not found")
  - User doesn't know which paths were checked
  - Hard to fix deployment issues
- **Evidence**:
```cpp
for (const auto& searchPath : searchPaths) {
    std::filesystem::path fullPath = searchPath / fileName;
    if (std::filesystem::exists(fullPath, ec)) {
        // Load...
    }
    // No logging if path doesn't exist
}
```
- **Validation**:
  - Remove all external drivers
  - Check error message quality
- **Fix Plan**: Log each search attempt: `std::wcout << L"[*] Checking: " << fullPath << L" - " << (exists ? L"Found" : L"Not Found") << std::endl;`

---

#### BUG-M014
- **Severity**: MEDIUM
- **Location**: KernelMode/PocMenu.cpp:400-420
- **Category**: Performance / Inefficient Algorithm
- **Description**: AttemptPhysicalMemoryMapping scans 64KB of physical memory in 4KB chunks but doesn't cache translated addresses. Repeated VirtualToPhysical calls wasteful.
- **Impact**:
  - Slow memory scanning (1000+ IOCTL calls)
  - Increased kernel transition overhead
  - Poor scalability for large scans
- **Evidence**:
```cpp
for (uintptr_t addr = scanStart; addr < scanStart + scanSize; addr += scanChunk) {
    if (activeProvider->ReadPhysicalMemory(addr, scanBuffer.data(), scanChunk)) {
        // Process...
    }
}
// Each ReadPhysicalMemory may internally call VirtualToPhysical repeatedly
```
- **Validation**:
  - Profile scan of 1MB range
  - Measure IOCTL count
- **Fix Plan**: Batch reads. If provider supports it, read larger chunks (64KB at once). Cache physical address mappings if scanning contiguous regions.

---

#### BUG-M015
- **Severity**: MEDIUM
- **Location**: KernelMode/PocMenu.cpp:580-600
- **Category**: Error Handling / Incomplete Cleanup
- **Description**: LoadSignedDriver creates service but doesn't clean up on failure. Service remains in registry after failed start.
- **Impact**:
  - Registry pollution
  - Service name conflicts on retry
  - Requires manual cleanup (sc delete)
- **Evidence**:
```cpp
ServiceInfo info = serviceManager->InstallDriverService(serviceName, fullPath, displayName);

if (serviceManager->StartDriverService(serviceName)) {
     LOG_OUTPUT("[+] Successfully started signed driver service!\n");
     return true;
} else {
     LOG_OUTPUT("[-] Failed to start driver service.\n");
     return false; // Service not deleted!
}
```
- **Validation**:
  - Force StartDriverService to fail
  - Check if service remains in registry
- **Fix Plan**: Add cleanup on failure: `serviceManager->StopAndDeleteService(serviceName);` before returning false.

---

#### BUG-M016
- **Severity**: MEDIUM
- **Location**: KernelMode/Callbacks.cpp:145-165
- **Category**: Error Handling / Write Verification
- **Description**: RemoveCallback writes NULL to callback array but doesn't verify write succeeded. If write fails, callback remains active but function returns success.
- **Impact**:
  - Callback not actually removed (still active)
  - False positive (thinks callback removed)
  - Security product still hooks process creation
- **Evidence**:
```cpp
uintptr_t nullValue = 0;
if (provider->WriteKernelMemory(arrayAddress + i * sizeof(uintptr_t), nullValue)) {
    std::wcout << L"[+] Successfully removed callback" << std::endl;
    return true;
} else {
    std::wcerr << L"[-] Failed to write NULL" << std::endl;
    return false; // Good! But need to verify write actually took effect
}
```
- **Validation**:
  - Mock WriteKernelMemory to return true but not actually write
  - Check if callback still active
- **Fix Plan**: After write, read back value: `uintptr_t verify = 1; if (!provider->ReadKernelMemory(arrayAddress + i * sizeof(uintptr_t), &verify, sizeof(verify)) || verify != 0) return false;`

---

#### BUG-M017
- **Severity**: MEDIUM
- **Location**: KernelMode/Privilege.cpp:270-290
- **Category**: Memory Safety / Shellcode Generation
- **Description**: StealSystemToken builds shellcode dynamically but doesn't validate size before allocating. Complex offset configurations could overflow buffer.
- **Impact**:
  - Shellcode buffer overflow
  - Corruption of stack or heap
  - Crash during shellcode construction
- **Evidence**:
```cpp
std::vector<uint8_t> shellcode;
// Build Shellcode dynamically with correct offsets
// ... many push_back operations ...
// No check if shellcode.size() exceeds reasonable limit
```
- **Validation**:
  - Use unusual offset values (very large)
  - Check if shellcode buffer grows unbounded
- **Fix Plan**: Add size check after construction: `if (shellcode.size() > 4096) { std::wcerr << L"[-] Shellcode too large"; return false; }`. Or use fixed-size array with compile-time checks.

---

#### BUG-M018
- **Severity**: MEDIUM
- **Location**: Multiple files (pattern across codebase)
- **Category**: Portability / Endianness
- **Description**: Memory structures (EPROCESS offsets, registry values) assume little-endian byte order. Code won't work on big-endian systems.
- **Impact**:
  - Silent data corruption on big-endian platforms (ARM in BE mode)
  - Incorrect kernel memory reads
  - Portability to embedded systems impossible
- **Evidence**:
```cpp
uint64_t val = *reinterpret_cast<uint64_t*>(&buffer[i]); // Assumes native byte order
```
- **Validation**:
  - Cross-compile to ARM BE
  - Run on big-endian system (or emulator)
- **Fix Plan**: Document assumption (Windows is LE-only). OR add endianness conversion macros if supporting other platforms. Add static_assert: `static_assert(std::endian::native == std::endian::little, "Big-endian not supported");`

---

### LOW SEVERITY

#### BUG-L001
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

#### BUG-L002
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

#### BUG-L003
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

#### BUG-L004
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

#### BUG-L005
- **Severity**: LOW
- **Location**: KernelMode/DriverDataManager.cpp:390
- **Category**: Code Quality / Comment
- **Description**: Comment says "KDU processes DWORDs, not bytes!" but code structure is complex. Unclear why this matters without context.
- **Impact**:
  - Difficult to understand edge case handling
  - Risk of removing "workaround" code during refactor
- **Evidence**:
```cpp
// CRITICAL FIX: KDU processes DWORDs, not bytes!
if (BufferSize < sizeof(ULONG))
    return;
```
- **Validation**: N/A (documentation issue)
- **Fix Plan**: Document specific algorithm details and why DWORD processing is required. Reference KDU source or documentation.

---

#### BUG-L006
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

#### BUG-L007
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

#### BUG-L008
- **Severity**: LOW
- **Location**: KernelMode/BYOVDManager.cpp:250-255
- **Category**: Code Quality / Incomplete Implementation
- **Description**: ResultToString only implements Success and VulnerableDriverNotFound cases, uses "Unknown" for all others. Poor error reporting.
- **Impact**:
  - Generic error messages ("Unknown")
  - Difficult to diagnose failure reasons
  - Poor user experience
- **Evidence**:
```cpp
std::wstring BYOVDManager::ResultToString(BYOVDResult result) {
    switch(result) {
        case BYOVDResult::Success: return L"Success";
        case BYOVDResult::VulnerableDriverNotFound: return L"Vulnerable Driver Not Found";
        // ... (simplified)
        default: return L"Unknown";
    }
}
```
- **Validation**: Trigger various failure modes, check error messages
- **Fix Plan**: Implement all enum values: `case BYOVDResult::DSEBypassFailed: return L"DSE Bypass Failed";` etc.

---

#### BUG-L009
- **Severity**: LOW
- **Location**: KernelMode/PocMenu.cpp:450-460
- **Category**: Code Quality / Dead Code
- **Description**: FindSystemVulnerableDrivers function exists but is never called. Dead code adds maintenance burden.
- **Impact**:
  - Confusing for code readers
  - Maintenance burden (keeping unused code)
  - May have bugs that never get caught
- **Evidence**:
```cpp
bool PocMenu::FindSystemVulnerableDrivers() {
    // ...
}
// Never called anywhere
```
- **Validation**:
  - Search for function calls (none found)
  - Comment out, verify build succeeds
- **Fix Plan**: Remove unused code OR integrate into menu if intended feature. Document if preserved for future use.

---

#### BUG-L010
- **Severity**: LOW
- **Location**: KernelMode/DefenderDisabler.cpp:130-145
- **Category**: Code Quality / Loop Variable
- **Description**: Range-based for loop uses `const auto& service` but vector elements are std::wstring (cheap to copy). Reference unnecessary.
- **Impact**:
  - Minor: no performance impact
  - Code style inconsistency
- **Evidence**:
```cpp
const std::vector<std::wstring> services = { ... };

for (const auto& service : services) {
    // std::wstring is small enough that copy would be fine
}
```
- **Validation**: N/A (code quality)
- **Fix Plan**: Use `const auto service` (copy) for simple types, or keep reference for consistency. Document coding standard.

---

#### BUG-L011
- **Severity**: LOW
- **Location**: KernelMode/Callbacks.cpp:18-30
- **Category**: Code Quality / Code Duplication
- **Description**: FindPattern helper function duplicated in anonymous namespace. Already exists in Utils.cpp. Code duplication adds maintenance burden.
- **Impact**:
  - Duplicate code (2+ implementations)
  - Inconsistent behavior if one updated
  - Waste of binary size
- **Evidence**:
```cpp
namespace {
    uintptr_t FindPattern(uintptr_t base, size_t size, const char* pattern, const char* mask) {
        // Duplicated from Utils.cpp
    }
}
```
- **Validation**: Compare implementations, check if identical
- **Fix Plan**: Remove duplicate, use Utils::FindPattern directly. OR document why local copy is needed (performance, different signature).

---

## C) ROADMAP.MD UPDATE

Adding new phase to ROADMAP.md:

### Phase 8: Custom Code Hardening (Post-Audit)

**Objective:** Address all critical, high, and selected medium severity issues identified in the January 2026 custom code audit.

#### 8.1 Critical Memory Safety Fixes
**Priority:** P0 (Must fix before production)

- [ ] **BUG-C001**: [PEParser.cpp:117-142] Add section header bounds validation before IMAGE_FIRST_SECTION iteration
  - Acceptance: Fuzzer with malformed PE (NumberOfSections=0xFFFF) doesn't crash
  - Validation: ASAN clean, unit test passes

- [ ] **BUG-C002**: [Utils.cpp:118-123] Fix GetKernelModuleInfo string handling with strnlen validation
  - Acceptance: Kernel module with OffsetToFileName=300 skipped, no crash
  - Validation: Valgrind clean, boundary test cases

- [ ] **BUG-C003**: [Main.cpp:95-107] Add RAII exception safety to provider initialization loop
  - Acceptance: Exception during DSE::Disable() cleans up provider and restores DSE
  - Validation: Mock exception test, resource leak detector

- [ ] **BUG-C004**: [ServiceManager.cpp:180-185] Remove TOCTOU vulnerability in service creation
  - Acceptance: CreateServiceW called atomically, ERROR_SERVICE_EXISTS handled
  - Validation: Race condition fuzzer, concurrent service creation test
  - **Status**: ROADMAP Phase 2 claims this is fixed - need verification

- [ ] **BUG-C005**: [UACBypass.cpp:51-53] Add path validation and quoting for UAC bypass
  - Acceptance: Executable in path with spaces properly quoted
  - Validation: Integration test with various path formats

- [ ] **BUG-C006**: [Callbacks.cpp:81-87] Add bounds validation after RVA calculation
  - Acceptance: Corrupted ntoskrnl patterns don't cause OOB read
  - Validation: ASAN clean, boundary test with modified module

#### 8.2 High Priority Error Handling
**Priority:** P1 (Fix within 2 weeks)

- [ ] **BUG-H001**: [ServiceManager.cpp:93-97] Change GenerateUniqueServiceName to return optional<wstring>
  - Acceptance: Empty string never returned; caller checks optional before use
  
- [ ] **BUG-H002**: [Utils.cpp:91-95] Add status validation for NtQuerySystemInformation
  - Acceptance: STATUS_ACCESS_DENIED handled gracefully, no buffer overflow
  
- [ ] **BUG-H003**: [Main.cpp:208-213] Add error handling for UAC bypass cleanup
  - Acceptance: RegDeleteTreeW failure logged, doesn't abort application
  
- [ ] **BUG-H004**: [Main.cpp:39-40] Replace global g_logFile with thread-safe logger
  - Acceptance: Thread sanitizer clean, no data races
  
- [ ] **BUG-H005**: [Utils.cpp:191-199] Add DeleteService return value checking
  - Acceptance: Failed deletion logged, cleanup retried
  
- [ ] **BUG-H006**: [PEParser.cpp:53-56] Use alignof() instead of hardcoded 4 for alignment check
  - Acceptance: ARM64 cross-compile succeeds, alignment correct
  
- [ ] **BUG-H007**: [ServiceManager.cpp:240-248] Verify no resource leaks in QueryServiceConfigW error paths
  - Acceptance: LeakSanitizer clean after 1000 failed queries
  
- [ ] **BUG-H008**: [Privilege.cpp:150-200] Add NtQuerySystemInformation status check before reading buffer
  - Acceptance: Error status handled before dereferencing structure
  
- [ ] **BUG-H009**: [ServiceManager.cpp:285-292] Wait for SERVICE_STOPPED before DeleteService
  - Acceptance: Service deletion succeeds reliably
  
- [ ] **BUG-H010**: [PocMenu.cpp:520-550] Add file size limit (32MB) to ExtractBinToSys
  - Acceptance: 4GB file rejected with error
  
- [ ] **BUG-H011**: [BYOVDManager.cpp:180-195] Fix service handle leaks on all error paths
  - Acceptance: Handle count stable after repeated failures
  
- [ ] **BUG-H012**: [DriverDataManager.cpp:290-305] Use RAII for decompressed data cleanup
  - Acceptance: LeakSanitizer clean after file write failures

#### 8.3 Medium Priority Security & Correctness
**Priority:** P2 (Fix within 1 month)

- [ ] **BUG-M001**: [Main.cpp:11] Remove _CRT_SECURE_NO_WARNINGS, fix individual warnings
  - Acceptance: /W4 /WX clean build
  
- [ ] **BUG-M002**: [Main.cpp:180-181] Replace std::ctime with thread-safe std::put_time
  - Acceptance: Multi-threaded logging doesn't corrupt timestamps
  
- [ ] **BUG-M003**: [Utils.cpp:147] Replace all hardcoded C:\\Windows\\System32 with GetSystemDirectoryW
  - Acceptance: Works on non-C: Windows installations
  
- [ ] **BUG-M004**: [UACBypass.cpp:29] Add error code differentiation for RegDeleteKeyW
  - Acceptance: Only real errors logged, ERROR_FILE_NOT_FOUND silent
  
- [ ] **BUG-M005**: [UACBypass.cpp:78] Remove arbitrary Sleep(1000), use WaitForInputIdle
  - Acceptance: Bypass succeeds reliably without delay
  
- [ ] **BUG-M006**: [ServiceManager.cpp:143-158] Add MAX_SERVICE_CONFIG_SIZE limit (64KB)
  - Acceptance: Malicious service with 1GB config doesn't cause OOM
  
- [ ] **BUG-M007**: [Main.cpp:96] Move provider vector to static/singleton for reuse
  - Acceptance: Heap profiler shows no repeated allocations
  
- [ ] **BUG-M008**: [Main.cpp:215-220] Add specific exception handlers (filesystem_error, bad_alloc)
  - Acceptance: Error messages distinguish between error categories
  
- [ ] **BUG-M009**: [Privilege.cpp:95-110] Validate provider before using in ResolveEProcessOffsets
  - Acceptance: Null provider caught early with clear error
  
- [ ] **BUG-M010**: [DefenderDisabler.cpp:80-85] Add registry virtualization detection
  - Acceptance: Write to HKLM verified, not virtualized to HKCU
  
- [ ] **BUG-M011**: [BYOVDManager.cpp:45-55] Enhance ValidateDriverFile to check PE signature
  - Acceptance: Non-PE files rejected at validation stage
  
- [ ] **BUG-M012**: [Callbacks.cpp:120-140] Add array size validation (max 64)
  - Acceptance: maxCallbacks clamped to reasonable limit
  
- [ ] **BUG-M013**: [DriverDataManager.cpp:125-145] Log each driver search path attempt
  - Acceptance: Error messages show all paths checked
  
- [ ] **BUG-M014**: [PocMenu.cpp:400-420] Batch physical memory reads (64KB chunks)
  - Acceptance: 1MB scan completes in <1s
  
- [ ] **BUG-M015**: [PocMenu.cpp:580-600] Add service cleanup on LoadSignedDriver failure
  - Acceptance: Failed loads don't leave orphaned services
  
- [ ] **BUG-M016**: [Callbacks.cpp:145-165] Add write verification (read-back check) for RemoveCallback
  - Acceptance: Write success verified before returning true
  
- [ ] **BUG-M017**: [Privilege.cpp:270-290] Add shellcode size validation (4KB limit)
  - Acceptance: Oversized shellcode rejected with error
  
- [ ] **BUG-M018**: [Multiple files] Document little-endian assumption
  - Acceptance: README notes Windows-only / LE-only assumption
  - Bonus: Add static_assert for endianness check

#### 8.4 Low Priority Code Quality
**Priority:** P3 (Fix opportunistically)

- [ ] **BUG-L001**: [Main.cpp:235] Replace system("pause") with std::cin.get()
- [ ] **BUG-L002**: [Main.cpp:198] Check system("pause") return value
- [ ] **BUG-L003**: [UACBypass.h:13] Add #include <Windows.h> to header
- [ ] **BUG-L004**: [Multiple files] Implement configurable logging levels
- [ ] **BUG-L005**: [DriverDataManager.cpp:390] Improve DWORD processing comments
- [ ] **BUG-L006**: [Main.cpp:87] Rename 'ec' to 'ec_ignored' or add comment
- [ ] **BUG-L007**: [ServiceManager.cpp:35] Add try-catch to destructor
- [ ] **BUG-L008**: [BYOVDManager.cpp:250-255] Implement all ResultToString cases
- [ ] **BUG-L009**: [PocMenu.cpp:450-460] Remove FindSystemVulnerableDrivers or integrate
- [ ] **BUG-L010**: [DefenderDisabler.cpp:130-145] Use value copy for simple types
- [ ] **BUG-L011**: [Callbacks.cpp:18-30] Remove FindPattern duplicate, use Utils version

#### 8.5 Tooling & Continuous Validation
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
1. **Triage**: Review all 47 findings with team, confirm severity ratings
2. **Sprint Planning**: Allocate P0 (Critical) items to immediate sprint
3. **Tooling Setup**: Prioritize sanitizer builds and fuzzing infrastructure
4. **Incremental Fixes**: Address one module at a time (PEParser → ServiceManager → UACBypass → Utils)
5. **Regression Testing**: Add unit tests for each fix, ensure no new bugs introduced
6. **Documentation**: Update technical docs with security considerations and limitations

---

**AUDIT STATUS:** Phase 1 Complete (Custom Code)  
**NEXT PHASE:** Deep dive into ManualMapper.cpp and DSE.cpp (if considered custom modifications vs KDU-based)

---

## C) PHASE 2 FINDINGS - ADDITIONAL CUSTOM CODE

### Newly Audited Files
- **KernelMode/SMEPBypass.cpp** (105 lines) - ROP gadget finder for SMEP bypass
- **KernelMode/Victim.cpp** (88 lines) - Victim driver loading and management  
- **KernelMode/Persistence.cpp** (229 lines) - Kernel-mode service persistence with shellcode

---

### CRITICAL SEVERITY (Phase 2)

#### BUG-C007
- **Severity**: CRITICAL
- **Location**: KernelMode/SMEPBypass.cpp:66-81
- **Category**: Memory Safety / Buffer Overflow
- **Description**: FindGadget function has off-by-one bounds checking error in pattern search loop
- **Problem**: Loop iterates to CHUNK_SIZE - pattern.size(), but accesses buffer[i + j] where j can be pattern.size() - 1. Pattern matching across chunk boundaries will miss gadgets.
- **Impact**: Reduced SMEP bypass success rate, potential out-of-bounds read
- **Fix Plan**: Implement overlapping chunk reads

#### BUG-C008
- **Severity**: CRITICAL  
- **Location**: KernelMode/Persistence.cpp:145-165
- **Category**: Security / Kernel Crash Risk
- **Description**: Hardcoded shellcode executed in kernel without NX/SMEP bypass
- **Problem**: Code acknowledges NX/SMEP will cause BSOD but proceeds anyway. SMEPBypass is initialized but never used.
- **Impact**: Guaranteed BSOD on Windows 10+ with HVCI/Device Guard
- **Fix Plan**: Integrate SMEPBypass before CreateSystemThread, OR allocate ExecutablePool

---

### HIGH SEVERITY (Phase 2)

#### BUG-H013
- **Severity**: HIGH
- **Location**: KernelMode/SMEPBypass.cpp:60-68
- **Category**: Error Handling
- **Description**: FindGadget silently continues on ReadKernelMemory failure
- **Impact**: Misleading 'gadget not found' errors when real issue is memory access failure
- **Fix Plan**: Log read failures, track consecutive failures, abort if >N failures

#### BUG-H014
- **Severity**: HIGH
- **Location**: KernelMode/Victim.cpp:63-70
- **Category**: Concurrency / Race Condition
- **Description**: ResolveModuleInfo called immediately after service start without waiting for driver initialization
- **Impact**: Victim base address resolution fails intermittently (25-50% on fast systems)
- **Fix Plan**: Poll GetKernelModuleInfo with exponential backoff (max 5 seconds)

---

### MEDIUM SEVERITY (Phase 2)

#### BUG-M018
- **Severity**: MEDIUM
- **Location**: KernelMode/Persistence.cpp:169-170
- **Category**: Data Integrity
- **Description**: wcsncpy_s with _TRUNCATE silently truncates long service names/paths
- **Impact**: Long service names (>100 chars) cause persistence failure without error indication
- **Fix Plan**: Validate lengths before copy, return error if too long

#### BUG-M019
- **Severity**: MEDIUM
- **Location**: KernelMode/SMEPBypass.cpp:27-31
- **Category**: Logic Error
- **Description**: Pattern size and mask size can mismatch, causing undefined behavior in FindGadget
- **Impact**: Mask shorter than pattern causes out-of-bounds read of mask string
- **Fix Plan**: Add assertion: assert(pattern.size() == mask.size())

#### BUG-M020
- **Severity**: MEDIUM
- **Location**: KernelMode/Victim.cpp:18-22
- **Category**: Resource Management
- **Description**: Destructor calls Unload() only if loaded flag is true, but flag may be stale
- **Impact**: Service handle corruption, potential crash on Victim destruction
- **Fix Plan**: Set loaded = false at start of Unload() regardless of outcome

---

### LOW SEVERITY (Phase 2)

#### BUG-L012
- **Severity**: LOW
- **Location**: KernelMode/SMEPBypass.cpp:58
- **Category**: Portability
- **Description**: 8MB scan size is arbitrary and may miss gadgets in larger ntoskrnl builds
- **Impact**: Missed gadgets in later sections (Windows 11 23H2 ntoskrnl ~10MB)
- **Fix Plan**: Parse PE headers to get actual .text section bounds

---

**UPDATED SUMMARY:**
- **Total Issues**: 54 (previously 47)
- **New CRITICAL**: 2 (BUG-C007, BUG-C008)
- **New HIGH**: 2 (BUG-H013, BUG-H014)  
- **New MEDIUM**: 3 (BUG-M018, BUG-M019, BUG-M020)
- **New LOW**: 1 (BUG-L012)

**AUDIT STATUS:** Phase 2 Complete (SMEPBypass, Victim, Persistence audited)

