#pragma once
#include <windows.h>
#include <string>

namespace KernelMode {
    /**
     * @class UACBypass
     * @brief Implements UAC bypass techniques to elevate privileges without user interaction.
     */
    class UACBypass {
    public:
        /**
         * @brief Checks if UAC is enabled on the system.
         * @return True if UAC is enabled, false otherwise.
         */
        static bool IsUacEnabled();

        /**
         * @brief Attempts to bypass UAC using the 'Fodhelper' method.
         * This modifies the HKCU registry to hijack the execution flow of fodhelper.exe,
         * which auto-elevates.
         * @param arguments Optional command line arguments to pass to the elevated process.
         * @return True if the exploit was triggered successfully.
         */
        static bool AttemptFodhelperBypass(const std::wstring& arguments = L"");
    };
}
