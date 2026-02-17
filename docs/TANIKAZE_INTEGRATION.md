# Tanikaze (KDU) Integration

**Date:** January 30, 2026

## Overview

We have successfully integrated the **Tanikaze** component from the KDU project into the KernelMode toolkit. Tanikaze (`drv64.dll`) serves as a comprehensive database and resource store for vulnerable drivers. By utilizing this component, we can leverage the extensive collection of drivers maintained by the KDU project without manually managing individual `.bin` files.

## Technical Implementation

### DriverDataManager Updates

The `DriverDataManager` class has been upgraded to support loading KDU-style databases:

1.  **Tanikaze Loading**: The manager now attempts to load `drv64.dll` at initialization.
2.  **Symbol Resolution**: It resolves the exported `gProvTable` symbol to access the `KDU_DB` structure.
3.  **Database Mapping**: It iterates through the KDU provider entries and populates the internal `DriverInfo` map.
4.  **Resource Extraction**: Instead of reading local files, it now extracts driver binaries directly from the `drv64.dll` resources (`RCDATA`) using the resource IDs defined in the table.

### Dependency

*   **File**: `drv64.dll`
*   **Location**: The DLL must be present in the application's working directory or the directory of the executable.
*   **Source**: This file is built from the `Source/Tanikaze` project in KDU.

### Benefits

*   **Centralized management**: Drivers are stored in a single, signed (or potentially signed) DLL.
*   **Updatability**: Updating the list of vulnerable drivers only requires replacing `drv64.dll`.
*   **Compatibility**: Direct compatibility with KDU's extensive driver research.

## Usage

The integration is automatic. When `KernelMode.exe` starts:
1.  It checks for `drv64.dll`.
2.  If found, it loads the drivers from it.
3.  If not found, it falls back to the legacy embedded/local file mechanism.

## Compilation Notes

The `KdutFlags` and `KDU_DB` structures have been mirrored in `DriverDataManager.h` to ensure binary compatibility with the KDU data structures.
