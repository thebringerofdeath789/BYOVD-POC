import os

content = """#include <windows.h>

// Placeholder definitions for embedded driver binaries.
// Used to satisfy linker dependencies when the actual resource blobs are missing or not compiled.
// These are intentionally dummy values to prevent bloating the binary.
// The applications logic will prefer loading drivers from disk (using LoadExternalDrivers).

extern "C" {
    // We must explicitly use 'extern' here because const variables in C++ have internal linkage by default.
    // Even inside extern "C", explicit extern ensures they are exported to the linker.
    
    // Tiny dummy buffers.
    extern const BYTE gdrv_bin_data[] = { 0x90, 0x90, 0x90, 0xC3 }; 
    extern const ULONG gdrv_bin_size = sizeof(gdrv_bin_data);

    extern const BYTE rtcore_bin_data[] = { 0x90, 0x90, 0x90, 0xC3 };
    extern const ULONG rtcore_bin_size = sizeof(rtcore_bin_data);

    extern const BYTE dbutil_bin_data[] = { 0x90, 0x90, 0x90, 0xC3 };
    extern const ULONG dbutil_bin_size = sizeof(dbutil_bin_data);
}
"""

with open(r"c:\Users\admin\Documents\Visual Studio 2022\Projects\BYOVD-POC\KernelMode\EmbeddedDrivers.cpp", "w") as f:
    f.write(content)
print("Reset EmbeddedDrivers.cpp to dummy data.")
