# BYOVD-POC Lifecycle Audit - Iteration 3 Report
## Exploitation Components Lifecycle Analysis

**Date**: December 2024  
**Iteration**: 3 of 3  
**Scope**: DSE bypass, Manual PE mapper, Main.cpp orchestration  
**Status**: Discovery Complete ✅

---

## Executive Summary

Iteration 3 audited the exploitation components responsible for defeating kernel protections and loading unsigned drivers. Analysis focused on:
- **DSE (Driver Signature Enforcement)** bypass class
- **ManualMapper** PE driver mapper to kernel memory
- **Main.cpp** orchestration layer and cleanup coordination

**Key Findings**:
- **6 lifecycle issues** identified (2 CRITICAL, 2 HIGH, 2 MEDIUM)
- **Critical kernel memory leaks** in ManualMapper
- **DSE state persistence** creates confusion after restore
- **Cleanup order not enforced** in orchestration layer

**Risk Assessment**: **CRITICAL**  
Kernel memory leaks accumulate with repeated operations. DSE state confusion can leave system vulnerable. No automated cleanup verification.

---

## Components Audited

### 1. DSE.cpp/h (187 lines)
**Purpose**: Bypass Windows Driver Signature Enforcement by patching g_CiOptions kernel variable

**Lifecycle Phases**:
```
[INIT] Constructor(provider*) → ciOptionsAddress=0, originalCiOptions=-1
   ↓
[HANDSHAKE] FindCiOptions() → pattern scan ci.dll, locate g_CiOptions address
   ↓
[ACTIVE] Disable() → read originalCiOptions, clear bits 0x6, write back
   ↓
[SHUTDOWN] Restore() → write originalCiOptions to ciOptionsAddress
   ↓
[ISSUE] State NOT reset: ciOptionsAddress, originalCiOptions remain set
```

**State Machine Diagram**:
```
    ┌──────────┐
    │ INIT     │ ciOptionsAddress=0, originalCiOptions=-1
    └────┬─────┘
         │ FindCiOptions()
         ▼
    ┌──────────┐
    │ LOCATED  │ ciOptionsAddress set, originalCiOptions captured
    └────┬─────┘
         │ Disable()
         ▼
    ┌──────────┐
    │ DISABLED │ Kernel patched, originalCiOptions preserved
    └────┬─────┘
         │ Restore()
         ▼
    ┌──────────┐
    │ RESTORED │ ⚠️ BUG: State looks like LOCATED (address/value still set)
    └──────────┘
         │ Disable() again?
         ▼ AMBIGUOUS STATE
```

**Issues Found**: 3 (LIFECYCLE-026, LIFECYCLE-027, LIFECYCLE-028)

---

### 2. ManualMapper.cpp/h (277 lines)
**Purpose**: Manually map PE driver to kernel memory, bypassing Windows loader and signature checks

**Lifecycle Phases**:
```
[INIT] Constructor(shared_ptr<IProvider>) → store provider
   ↓
[LOAD] MapDriver(driverPath) → parse PE, allocate kernel memory
   ↓
[ALLOCATE] remoteImageBase = AllocateKernelMemory(imageSize)
   ↓
[ALLOCATE] shellcodeExec = AllocateKernelMemory(shellcodeSize)
   ↓
[EXECUTE] CreateSystemThread(shellcodeExec) → call DriverEntry
   ↓
[RETURN] Return remoteImageBase
   ↓
[ISSUE] shellcodeExec address lost → MEMORY LEAK
[ISSUE] No cleanup method → remoteImageBase never freed
```

**Memory Lifecycle**:
```
MapDriver() Allocations:
┌─────────────────────┐
│ remoteImageBase     │ Kernel pool (imageSize bytes)
│ (driver image)      │ ✅ Freed on early errors
│                     │ ❌ Never freed on success
└─────────────────────┘
         +
┌─────────────────────┐
│ shellcodeExec       │ Kernel executable pool (~100 bytes)
│ (DriverEntry stub)  │ ❌ Address lost immediately
│                     │ ❌ NEVER freed
└─────────────────────┘
```

**Error Handling Audit**:
| Error Point | remoteImageBase Freed? | shellcodeExec Freed? |
|-------------|------------------------|----------------------|
| Import resolution fails (L145) | ✅ Yes | N/A (not allocated yet) |
| WriteKernelMemory fails (L159) | ✅ Yes | N/A |
| Shellcode alloc fails (L246) | ❌ **BUG: NO** | N/A |
| Shellcode write fails (L253) | ❌ **BUG: NO** | ✅ Yes (line 253) |
| Success path (L275) | ❌ **BUG: NO** | ❌ **BUG: NO** |

**Issues Found**: 2 (LIFECYCLE-029, LIFECYCLE-030)

---

### 3. Main.cpp Orchestration (260 lines)
**Purpose**: Coordinate provider initialization, DSE bypass, driver loading, and cleanup

**Success Path Cleanup Sequence**:
```cpp
// Line 154-170 (SilentRK load success)
std::wcout << L"[*] Restoring DSE..." << std::endl;
dse.Restore();  // ⚠️ Return value IGNORED

provider->Deinitialize();  // Always called
// ServiceManager destructor runs automatically
```

**Cleanup Dependencies**:
```
┌────────────────┐
│ DSE::Restore() │ Must succeed before provider cleanup
└───────┬────────┘
        │ ⚠️ No verification
        ▼
┌──────────────────────┐
│ provider->Deinit()   │ Closes driver handle, removes service
└───────┬──────────────┘
        │
        ▼
┌──────────────────────┐
│ ~ServiceManager()    │ Final cleanup
└──────────────────────┘
```

**Observed Issues**:
1. Restore() failure silently ignored
2. No retry mechanism for DSE restore
3. Provider deinitialized even if restore failed (loses ability to retry)
4. No exception handling around cleanup sequence

**Issues Found**: 1 (LIFECYCLE-031)

---

## Critical Issues Detail

### LIFECYCLE-026: DSE State Not Reset After Restore() [CRITICAL]

**Location**: [DSE.cpp:177-186](../KernelMode/DSE.cpp#L177-L186)

**Description**:  
After `Restore()` writes originalCiOptions back to kernel, the DSE object's state remains:
- `ciOptionsAddress` still points to g_CiOptions
- `originalCiOptions` still holds captured value
- No flag indicates "restored" state

**Code**:
```cpp
bool DSE::Restore() {
    if (!ciOptionsAddress || originalCiOptions == -1) {
        return false;
    }
    
    uint32_t val = (uint32_t)originalCiOptions;
    if (provider->WriteKernelMemory(ciOptionsAddress, &val, sizeof(val))) {
        std::wcout << L"[+] DSE Restored." << std::endl;
        return true;  // ⚠️ State NOT reset
    }
    return false;
}
```

**State Confusion Scenario**:
```cpp
DSE dse(provider);
dse.Disable();   // Captures originalCiOptions=0x6, sets address
dse.Restore();   // Writes 0x6 back, but address/value still set
dse.Disable();   // Skips FindCiOptions() (line 137 early return)
                 // Uses STALE address/value
dse.Restore();   // Restores same value again (appears idempotent but misleading)
```

**Impact**:
- Object reuse after Restore() uses stale state
- Cannot distinguish "never used", "active", or "restored" states
- Multiple Restore() calls appear idempotent by accident, not design

**Recommendation**:
```cpp
bool DSE::Restore() {
    if (!ciOptionsAddress || originalCiOptions == -1) {
        return false;
    }
    
    uint32_t val = (uint32_t)originalCiOptions;
    if (provider->WriteKernelMemory(ciOptionsAddress, &val, sizeof(val))) {
        std::wcout << L"[+] DSE Restored." << std::endl;
        
        // Reset state
        ciOptionsAddress = 0;
        originalCiOptions = -1;
        
        return true;
    }
    return false;
}
```

---

### LIFECYCLE-029: ManualMapper Leaks Kernel Memory On Failure [CRITICAL]

**Location**: [ManualMapper.cpp:236-254](../KernelMode/ManualMapper.cpp#L236-L254)

**Description**:  
`MapDriver()` allocates `remoteImageBase` for driver image but inconsistently frees it on error. Shellcode allocation failure (line 246) and write failure (line 253) do NOT free remoteImageBase.

**Code (Error Path at Line 246)**:
```cpp
uintptr_t shellcodeExec = provider->AllocateKernelMemory(sizeof(driverEntryShellcode), &shellcodePhys);
if (!shellcodeExec) {
    std::wcerr << L"[-] Failed to allocate kernel memory for shellcode." << std::endl;
    // ⚠️ BUG: remoteImageBase NOT freed here (allocated at line 112)
    return 0;  // LEAK: imageSize bytes lost in kernel pool
}
```

**Memory Leak Analysis**:
| Scenario | remoteImageBase Size | Leaked Memory | Frequency |
|----------|----------------------|---------------|-----------|
| RTCore64.sys mapping | ~20 KB | 20 KB | Per attempt |
| SilentRK.sys mapping | ~50 KB | 50 KB | Per attempt |
| 10 failed attempts | 50 KB each | **500 KB** | Session |

**Kernel Pool Impact**:
- NonPagedPool exhaustion risk
- No cleanup until system reboot
- Accumulates across multiple tool runs

**Fix**:
```cpp
uintptr_t shellcodeExec = provider->AllocateKernelMemory(sizeof(driverEntryShellcode), &shellcodePhys);
if (!shellcodeExec) {
    std::wcerr << L"[-] Failed to allocate kernel memory for shellcode." << std::endl;
    provider->FreeKernelMemory(remoteImageBase, imageSize);  // ADD THIS
    return 0;
}
```

---

### LIFECYCLE-030: ManualMapper Shellcode Memory Never Freed [HIGH]

**Location**: [ManualMapper.cpp:236-275](../KernelMode/ManualMapper.cpp#L236-L275)

**Description**:  
Shellcode memory allocated at line 240 is used for DriverEntry stub execution. After CreateSystemThread() and 2-second wait, shellcode address is discarded. No cleanup method exists.

**Code**:
```cpp
uintptr_t shellcodeExec = provider->AllocateKernelMemory(sizeof(driverEntryShellcode), &shellcodePhys);
if (!shellcodeExec) { /* ... */ }

// Write shellcode
provider->WriteKernelMemory(shellcodeExec, driverEntryShellcode, sizeof(driverEntryShellcode));

// Execute
HANDLE hThread = provider->CreateSystemThread(shellcodeExec, (PVOID)remoteImageBase);
WaitForSingleObject(hThread, 2000);  // Wait for execution
CloseHandle(hThread);

// ... zero headers ...
return remoteImageBase;  // ⚠️ shellcodeExec address LOST
```

**Shellcode Lifecycle**:
```
Allocate shellcodeExec (line 240)
    ↓
Write stub to kernel (line 248)
    ↓
CreateSystemThread(shellcodeExec) (line 257)
    ↓
Wait 2 seconds (line 259)
    ↓
Return remoteImageBase (line 275)
    ↓
⚠️ shellcodeExec address lost → PERMANENT LEAK
```

**Impact**:
- ~100 bytes executable kernel memory leaked per MapDriver() success
- Memory remains RWX (Read-Write-Execute) in kernel
- Security concern: leftover executable shellcode in kernel pool
- No way to free memory later (address lost)

**Proposed Fix** (Add Cleanup Method):
```cpp
class ManualMapper {
private:
    std::vector<std::pair<uintptr_t, size_t>> allocatedMemory;  // Track allocations
    
public:
    uintptr_t MapDriver(const std::wstring& driverPath) {
        // ... existing code ...
        allocatedMemory.push_back({remoteImageBase, imageSize});
        allocatedMemory.push_back({shellcodeExec, sizeof(driverEntryShellcode)});
        return remoteImageBase;
    }
    
    void Cleanup() {
        for (auto& [addr, size] : allocatedMemory) {
            provider->FreeKernelMemory(addr, size);
        }
        allocatedMemory.clear();
    }
    
    ~ManualMapper() {
        Cleanup();
    }
};
```

---

## Transition Verification

### DSE State Transitions

| Transition | Implementation | Status | Notes |
|------------|----------------|--------|-------|
| INIT → LOCATED | FindCiOptions() | ✅ Works | Pattern scan successful |
| LOCATED → DISABLED | Disable() | ✅ Works | Captures original, writes patched |
| DISABLED → RESTORED | Restore() | ⚠️ Incomplete | Writes correct value but state not reset |
| RESTORED → INIT | (missing) | ❌ **MISSING** | No state reset method |
| DISABLED → DISABLED | Disable() again | ⚠️ Partial | Early return (line 137), doesn't re-read original |
| RESTORED → DISABLED | Disable() after Restore() | ⚠️ Works but misleading | Uses stale state |

**Critical Gap**: No transition from RESTORED back to INIT. Object reuse after Restore() uses stale state.

### ManualMapper State Transitions

| Transition | Implementation | Status | Notes |
|------------|----------------|--------|-------|
| INIT → ALLOCATED | AllocateKernelMemory() | ✅ Works | Allocates remoteImageBase |
| ALLOCATED → MAPPED | WriteKernelMemory() | ✅ Works | Copies driver to kernel |
| MAPPED → EXECUTED | CreateSystemThread() | ✅ Works | Runs DriverEntry |
| EXECUTED → CLEANED | (missing) | ❌ **MISSING** | No cleanup method exists |
| ERROR → INIT | FreeKernelMemory() | ⚠️ Inconsistent | Only some error paths free memory |

**Critical Gap**: No EXECUTED → CLEANED transition. Memory leaks on success and late-stage failures.

### Main.cpp Cleanup Coordination

| Cleanup Step | Order | Verification | Status |
|--------------|-------|--------------|--------|
| DSE Restore | 1 | Return value ignored | ⚠️ No verification |
| Provider Deinit | 2 | Always called | ✅ Reliable |
| ServiceManager Destructor | 3 | Automatic | ✅ Reliable |

**Critical Gap**: DSE restore failure not detected. No retry mechanism if restore fails.

---

## Recommendations

### Priority 0 (Fix Before Production)

1. **LIFECYCLE-029**: Fix ManualMapper error path leaks
   - Add `FreeKernelMemory(remoteImageBase)` to ALL error paths after line 112
   - Verify: Run MapDriver() with forced shellcode allocation failure, check kernel pool
   
2. **LIFECYCLE-030**: Implement ManualMapper cleanup
   - Track all kernel allocations in class member
   - Add Cleanup() method to free tracked memory
   - Call Cleanup() in destructor
   - Verify: Load driver, destroy ManualMapper, check kernel pool

3. **LIFECYCLE-026**: Reset DSE state after Restore()
   - Set ciOptionsAddress = 0, originalCiOptions = -1 after successful restore
   - Verify: Call Disable() → Restore() → Disable() and ensure second Disable() calls FindCiOptions()

### Priority 1 (Security Hardening)

4. **LIFECYCLE-027**: Make DSE::Disable() truly idempotent
   - Remove early return in FindCiOptions() OR re-read originalCiOptions on every Disable()
   - Add lastReadTimestamp to detect stale originalCiOptions
   
5. **LIFECYCLE-031**: Enforce cleanup order in Main.cpp
   - Check Restore() return value, retry if false
   - Add timeout for restore retries (3 attempts, 500ms delay)
   - Log failure if restore never succeeds

### Priority 2 (Maintainability)

6. **LIFECYCLE-028**: Validate provider lifetime in DSE
   - Change constructor to take `shared_ptr<IProvider>` instead of raw pointer
   - Check provider->IsInitialized() before every operation
   
7. **Add state machine enforcement**:
   - DSE: Add `enum class State { INIT, LOCATED, DISABLED, RESTORED }` member
   - ManualMapper: Add `enum class State { INIT, ALLOCATED, MAPPED, EXECUTED, CLEANED }` member
   - Assert valid transitions before state changes

---

## Testing Strategy

### DSE State Tests
```cpp
void TestDSEStateReset() {
    DSE dse(provider);
    
    // First cycle
    assert(dse.Disable());
    assert(dse.Restore());
    
    // State should be reset - FindCiOptions() should execute again
    MockProvider* mock = static_cast<MockProvider*>(provider);
    mock->ResetCallCounts();
    
    assert(dse.Disable());
    assert(mock->GetFindPatternCallCount() > 0);  // Should scan again, not use stale address
}
```

### ManualMapper Leak Tests
```cpp
void TestManualMapperCleanup() {
    size_t poolBefore = GetKernelPoolUsage();
    
    {
        ManualMapper mapper(provider);
        mapper.MapDriver(L"test_driver.sys");
    }  // Destructor should free memory
    
    size_t poolAfter = GetKernelPoolUsage();
    assert(poolBefore == poolAfter);  // No leak
}
```

### Orchestration Order Tests
```cpp
void TestCleanupOrder() {
    MockProvider mock;
    mock.SetRestoreFailureMode(true);  // Simulate restore failure
    
    DSE dse(&mock);
    dse.Disable();
    
    bool restored = dse.Restore();
    assert(!restored);  // Should detect failure
    
    // Verify retry mechanism triggered
    assert(mock.GetRestoreAttempts() == 3);
}
```

---

## Iteration 3 Statistics

| Metric | Count |
|--------|-------|
| Components Audited | 3 |
| Files Analyzed | 5 |
| Lines Analyzed | ~700 |
| Issues Found | 6 |
| Critical Issues | 2 |
| High Issues | 2 |
| Medium Issues | 2 |
| Transitions Verified | 13 |
| Code Examples Created | 8 |

---

## Cumulative Audit Statistics (All 3 Iterations)

| Metric | Total |
|--------|-------|
| **Components Audited** | 11 |
| **Files Analyzed** | 15+ |
| **Lines Analyzed** | ~3,300 |
| **Total Issues Found** | **31** |
| **Critical Issues** | **9** |
| **High Issues** | **13** |
| **Medium Issues** | **9** |
| **Low Issues** | 0 |
| **Transitions Verified** | 39 |

---

## Next Steps

1. **Prioritize P0 fixes**: Memory leaks in ManualMapper (LIFECYCLE-029, LIFECYCLE-030)
2. **Security review**: Audit all kernel memory allocation/free pairs
3. **Add state tracking**: Implement state machine enums in DSE and ManualMapper
4. **Enhance logging**: Log all state transitions for debugging
5. **Write tests**: Create unit tests for all 6 Iteration 3 issues

**Audit Status**: ✅ **COMPLETE** (3/3 iterations)  
**Next Phase**: Remediation and testing

---

*Report generated as part of BYOVD-POC Lifecycle Audit series*  
*See also: LIFECYCLE_AUDIT_ITERATION_1.md, LIFECYCLE_AUDIT_ITERATION_2.md*
