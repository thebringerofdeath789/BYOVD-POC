/**
 * @file ManualMapper.h
 * @author Gregory King
 * @date August 14, 2025
 * @brief This file contains the declaration of the ManualMapper class.
 *
 * The ManualMapper class provides functionality for manually mapping kernel
 * drivers into memory, bypassing standard driver loading mechanisms.
 */

#pragma once

#include "Providers/IProvider.h"
#include <string>
#include <memory>
#include <vector>
#include <Windows.h>

namespace KernelMode {
    /**
     * @class ManualMapper
     * @brief Manages the manual mapping of a kernel driver.
     *
     * This class uses a provider to perform all necessary kernel memory
     * operations to load a driver from a file on disk directly into
     * kernel memory.
     */
    class ManualMapper {
    public:
        /**
         * @brief Constructs a ManualMapper with a given provider.
         * @param provider A shared pointer to an active IProvider for kernel memory operations.
         */
        explicit ManualMapper(std::shared_ptr<Providers::IProvider> provider);

        /**
         * @brief Manually maps a driver from the given path into kernel memory.
         * @param driverPath The path to the 64-bit driver file.
         * @return The base address of the mapped driver in the kernel, or 0 on failure.
         */
        uintptr_t MapDriver(const std::wstring& driverPath);

    private:
        /**
         * @brief Resolves the imports for the driver image.
         * @param imageBuffer The local buffer containing the driver file.
         * @return True if all imports were resolved, false otherwise.
         */
        bool ResolveImports(std::vector<char>& imageBuffer);

        /**
         * @brief Applies base relocations to the driver image.
         * @param imageBuffer The local buffer containing the driver file.
         * @param delta The difference between the allocated base and the PE's preferred ImageBase.
         */
        void ApplyRelocations(std::vector<char>& imageBuffer, uintptr_t delta);

        std::shared_ptr<Providers::IProvider> provider;
        
        // Track kernel memory allocations for proper cleanup
        struct KernelAllocation {
            uintptr_t address;
            size_t size;
        };
        std::vector<KernelAllocation> allocations;
        
    public:
        /**
         * @brief Cleanup all allocated kernel memory.
         * This should be called before destroying the mapper or on error.
         */
        void Cleanup();
        
        /**
         * @brief Destructor ensures cleanup.
         */
        ~ManualMapper();
    };
}