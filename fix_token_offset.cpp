// Forward declarations
WINDOWS_VERSION GetWindowsVersion();
NTSTATUS GetTokenOffsetsForVersion(WINDOWS_VERSION Version, PTOKEN_OFFSETS TokenOffsets);

// Helper function implementation
NTSTATUS GetTokenOffset(
    _Out_ PULONG TokenOffset
)
{
    if (!TokenOffset) {
        return STATUS_INVALID_PARAMETER;
    }

    WINDOWS_VERSION version = GetWindowsVersion();
    if (version == WINDOWS_UNSUPPORTED || version == WINDOWS_UNKNOWN) {
        SRK_DEBUG_PRINT("Unsupported Windows version for token offset\n");
        // Fallback or fail? Fail is safer to avoid BSOD.
        return STATUS_NOT_SUPPORTED;
    }

    TOKEN_OFFSETS offsets = { 0 };
    NTSTATUS status = GetTokenOffsetsForVersion(version, &offsets);
    if (!NT_SUCCESS(status)) {
        SRK_DEBUG_PRINT("Failed to get token offsets\n");
        return status;
    }

    if (offsets.TokenOffset == 0) {
        return STATUS_NOT_FOUND;
    }

    *TokenOffset = offsets.TokenOffset;
    return STATUS_SUCCESS;
}
