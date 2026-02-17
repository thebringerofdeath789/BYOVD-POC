#include <iostream>
#include <fstream>
#include <vector>
#include <Windows.h>
#include "../KernelMode/Resources/DriverDataManager.h"

int main() {
    using namespace KernelMode::Resources;
    
    std::wcout << L"[*] Testing KDU decompression and signature validation" << std::endl;
    std::wcout << L"[*] Using key 0x" << std::hex << 0xF62E6CE0 << std::dec << std::endl;
    
    // Initialize the DriverDataManager to test the enhanced system
    DriverDataManager& manager = DriverDataManager::GetInstance();
    if (!manager.Initialize()) {
        std::wcerr << L"[-] Failed to initialize DriverDataManager" << std::endl;
        return 1;
    }
    
    // Test extraction and validation with a driver
    std::wcout << L"\n[*] Testing driver extraction and validation..." << std::endl;
    std::wstring testOutputPath = L"test_extracted_driver.sys";
    
    if (manager.ExtractDriver(DRIVER_ID_GDRV, testOutputPath)) {
        std::wcout << L"[+] Successfully extracted driver to " << testOutputPath << std::endl;
        
        // Test signature validation
        SignatureInfo sigInfo = {};
        if (manager.ValidateDriverSignature(testOutputPath, sigInfo)) {
            std::wcout << L"[+] Signature validation completed:" << std::endl;
            std::wcout << L"    Result: " << sigInfo.Result << std::endl;
            std::wcout << L"    Subject: " << sigInfo.SubjectName << std::endl;
            std::wcout << L"    Trust Score: " << sigInfo.TrustScore << std::endl;
        } else {
            std::wcout << L"[!] Signature validation failed" << std::endl;
        }
    } else {
        std::wcout << L"[-] Driver extraction failed" << std::endl;
    }
    
    // Original decompression test
    std::wcout << L"\n[*] Testing direct decompression..." << std::endl;
    std::ifstream file(L"..\\..\\KernelMode\\drv\\gdrv.bin", std::ios::binary | std::ios::ate);
    if (!file) {
        std::wcerr << L"[-] Could not open gdrv.bin" << std::endl;
        return 1;
    }
    
    auto size = file.tellg();
    file.seekg(0);
    std::vector<BYTE> data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);
    file.close();
    
    std::wcout << L"[+] Loaded " << size << L" bytes from gdrv.bin" << std::endl;
    
    // Test decompression
    SIZE_T decompressedSize = 0;
    PVOID decompressedData = DriverDataManager::DecompressDriverData(
        data.data(), 
        size, 
        &decompressedSize, 
        0xF62E6CE0
    );
    
    if (decompressedData && decompressedSize > 0) {
        std::wcout << L"[+] Successfully decompressed! Size: " << decompressedSize << L" bytes" << std::endl;
        
        // Check if it's a valid PE file
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)decompressedData;
        if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
            std::wcout << L"[+] Valid PE file detected!" << std::endl;
            
            // Write to test file
            std::ofstream outFile(L"test_decompressed.sys", std::ios::binary);
            outFile.write(reinterpret_cast<const char*>(decompressedData), decompressedSize);
            outFile.close();
            std::wcout << L"[+] Written to test_decompressed.sys" << std::endl;
        } else {
            std::wcout << L"[!] Not a valid PE file" << std::endl;
        }
        
        HeapFree(GetProcessHeap(), 0, decompressedData);
    } else {
        std::wcout << L"[-] Decompression failed" << std::endl;
    }
    
    // List all available drivers
    std::wcout << L"\n[*] Available drivers with validation status:" << std::endl;
    manager.ListAllDrivers();
    
    return 0;
}
