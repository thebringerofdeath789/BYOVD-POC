// Helper to get pointer arithmetic working
#define GetPointer(ptr) ((PUCHAR)(ptr))

NTSTATUS HookSystemCall(
      _In_ PCWSTR SystemCallName,
      _Out_ PVOID* OriginalFunction,
      _In_ PVOID HookFunction,
      _Inout_ PSYSTEM_CALL_HOOK HookContext
  )
  {
      UNICODE_STRING routineName;
      RtlInitUnicodeString(&routineName, SystemCallName);

      PVOID systemCallAddress = MmGetSystemRoutineAddress(&routineName);
      if (!systemCallAddress) {
          SRK_DEBUG_PRINT("Failed to resolve %wZ\n", &routineName);
          return STATUS_NOT_FOUND;
      }

      // [FIX] Save System Call Address and Original Bytes for Unload
      HookContext->OriginalAddress = systemCallAddress;
      RtlCopyMemory(HookContext->OriginalBytes, systemCallAddress, JMP_SIZE);

      // [FIX] Create Trampoline (Executes stolen bytes -> Jumps back)
      // Size: 28 bytes.
      PVOID trampoline = ExAllocatePoolWithTag(NonPagedPool, JMP_SIZE * 2, 'krhT');
      if (!trampoline) {
          return STATUS_INSUFFICIENT_RESOURCES;
      }
      
      // 1. Copy stolen bytes to trampoline
      RtlCopyMemory(trampoline, systemCallAddress, JMP_SIZE);
      
      // 2. Write Jump Back to Original Function + JMP_SIZE
      UCHAR jumpBack[JMP_SIZE] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
      ULONG_PTR destBack = (ULONG_PTR)systemCallAddress + JMP_SIZE;
      *(PVOID*)&jumpBack[6] = (PVOID)destBack;
      
      RtlCopyMemory((GetPointer(trampoline) + JMP_SIZE), jumpBack, JMP_SIZE);

      // 3. Set output generic function pointer to Trampoline
      *OriginalFunction = trampoline;
      HookContext->PatchedBytes[0] = 0xAA; // Mark as holding trampoline
      *(PVOID*)&HookContext->PatchedBytes[6] = trampoline; // Store trampoline ptr in unused slots

      // Create patch for Target Function (Jump to Hook)
      UCHAR patchedBytes[JMP_SIZE] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
      *(PVOID*)&patchedBytes[6] = HookFunction;
      
      // Write the patch
      KIRQL oldIrql = KeRaiseIrqlToDpcLevel();
      ULONG_PTR cr0 = __readcr0();
      __writecr0(cr0 & ~0x10000); // Disable WP

      RtlCopyMemory(systemCallAddress, patchedBytes, JMP_SIZE);

      __writecr0(cr0); // Restore WP
      KeLowerIrql(oldIrql);
  
      return STATUS_SUCCESS;
  }
