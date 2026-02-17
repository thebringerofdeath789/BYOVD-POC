/**
 * @file DriverDataManager.cpp
 * @author Gregory King
 * @date August 14, 2025
 * @brief KDU-style driver resource management implementation.
 *
 * This file implements comprehensive driver resource management following KDU patterns
 * with support for embedded resources, external file loading, decompression, and
 * automatic driver selection based on system suitability.
 */

#include "DriverDataManager.h"
#include "../Utils.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <filesystem>
#include <winternl.h>

namespace KernelMode {
    namespace Resources {

        DriverDataManager& DriverDataManager::GetInstance() {
            static DriverDataManager instance;
            return instance;
        }

        DriverDataManager::~DriverDataManager() {
            if (hTanikaze) {
                FreeLibrary(hTanikaze);
                hTanikaze = NULL;
            }
        }

        bool DriverDataManager::Initialize() {
            if (initialized) return true;

            std::wcout << L"[*] Initializing KDU-style Driver Data Manager..." << std::endl;

            // 1. Load Tanikaze (drv64.dll) as the primary source
            if (LoadTanikaze()) {
                std::wcout << L"[+] Driver Data Manager initialized using Tanikaze (drv64.dll)." << std::endl;
            } else {
                std::wcerr << L"[-] Failed to load Tanikaze (drv64.dll). Please ensure it is present." << std::endl;
                // Fallback Removed: We are relying on KDU Tanikaze integration.
                return false;
            }
            
            // Only consider initialized if we have at least one driver
            if (drivers.empty()) {
                return false;
            }

            initialized = true;
            std::wcout << L"[+] Driver Data Manager initialized with " 
                << drivers.size() << L" drivers." << std::endl;
            
            // ListAllDrivers(); // Verbose
            return true;
        }

        bool DriverDataManager::LoadTanikaze(const std::wstring& dllPath) {
            std::wcout << L"[*] Attempting to load Tanikaze library: " << dllPath << std::endl;
            
            hTanikaze = LoadLibraryW(dllPath.c_str());
            if (!hTanikaze) {
                // Try looking in current directory explicitly if just filename provided
                wchar_t currentDir[MAX_PATH];
                if (GetCurrentDirectoryW(MAX_PATH, currentDir)) {
                    std::wstring fullPath = std::wstring(currentDir) + L"\\" + dllPath;
                    hTanikaze = LoadLibraryW(fullPath.c_str());
                }
                
                if (!hTanikaze) {
                    std::wcout << L"[-] Failed to load " << dllPath << L". Error: " << GetLastError() << std::endl;
                    return false;
                }
            }

            // Resolve gProvTable
            PKDU_DB ProvTable = (PKDU_DB)GetProcAddress(hTanikaze, "gProvTable");
            if (!ProvTable) {
                std::wcerr << L"[-] Failed to find gProvTable in Tanikaze dll." << std::endl;
                FreeLibrary(hTanikaze);
                hTanikaze = NULL;
                return false;
            }

            std::wcout << L"[+] Tanikaze loaded. Found " << ProvTable->NumberOfEntries << L" providers." << std::endl;

            // Iterate and populate drivers map
            for (ULONG i = 0; i < ProvTable->NumberOfEntries; i++) {
                KDU_DB_ENTRY& entry = ProvTable->Entries[i];
                
                auto info = std::make_unique<DriverInfo>();
                info->DriverId = entry.ProviderId;
                info->DriverName = entry.Desciption ? entry.Desciption : L"Unknown Driver";
                info->FileName = entry.DriverName ? std::wstring(entry.DriverName) + L".sys" : L"driver.sys";
                info->MinWindowsBuild = entry.MinNtBuildNumberSupport;
                info->MaxWindowsBuild = entry.MaxNtBuildNumberSupport;
                
                // Set reliability/suitability based on flags
                info->IsBlocked = false; // We assume they are usable unless blacklisted later
                info->ReliabilityScore = 80;
                
                if (entry.Flags & KDUPROV_FLAGS_SUPPORT_HVCI) info->ReliabilityScore += 10;
                if (entry.Flags & KDUPROV_FLAGS_SIGNATURE_WHQL) info->ReliabilityScore += 5;

                // Load Resource Data Immediately? 
                // Alternatively, we can lazy load, but our logic expects DriverData to be present for comparison.
                // We'll lazy load if we change architecture, but for now let's try to fetch size or data.
                
                HRSRC hResource = FindResourceW(hTanikaze, MAKEINTRESOURCEW(entry.ResourceId), RT_RCDATA);
                if (hResource) {
                    HGLOBAL hGlobal = LoadResource(hTanikaze, hResource);
                    if (hGlobal) {
                        DWORD resourceSize = SizeofResource(hTanikaze, hResource);
                        PVOID resourceData = LockResource(hGlobal);
                        if (resourceData && resourceSize > 0) {
                            info->DriverData.assign(static_cast<BYTE*>(resourceData), static_cast<BYTE*>(resourceData) + resourceSize);
                            info->DriverDataSize = resourceSize;
                            
                            // Map source path to "Tanikaze Resource" for debugging
                            info->SourcePath = L"Tanikaze::Resource::" + std::to_wstring(entry.ResourceId);
                            info->CVE = L"Unknown (KDU)";
                            info->Description = entry.SignerName ? std::wstring(entry.SignerName) : L"Internal Provider";

                            // Add to map - overwrite if exists (Tanikaze takes precedence)
                            drivers[entry.ProviderId] = std::move(info);
                        }
                    }
                }
            }

            return !drivers.empty();
        }





        bool DriverDataManager::ExtractDriver(ULONG driverId, const std::wstring& outputPath) {
            auto it = drivers.find(driverId);
            if (it == drivers.end()) {
                std::wcerr << L"[-] Driver ID " << driverId << L" not found." << std::endl;
                return false;
            }

            const auto& driver = it->second;
            if (driver->DriverData.empty()) {
                std::wcerr << L"[-] Driver " << driver->DriverName << L" has no data." << std::endl;
                return false;
            }

            // Extract driver data to file
            std::ofstream outFile(outputPath, std::ios::binary);
            if (!outFile.is_open()) {
                std::wcerr << L"[-] Failed to create output file: " << outputPath << std::endl;
                return false;
            }

            // Try KDU-style decompression with multiple keys first
            SIZE_T decompressedSize = 0;
            PVOID decompressedData = nullptr;
            
            // Known KDU decryption keys
            std::vector<ULONG> kdutKeys = {
                0xF62E6CE0,  // Official KDU key from source
                0x0783C1E0,  // Discovered Key for this artifact
                0x12345678,  // Alternative key
                0x00000000   // No encryption
            };

            for (ULONG key : kdutKeys) {
                decompressedData = DecompressDriverData(
                    reinterpret_cast<PVOID>(const_cast<BYTE*>(driver->DriverData.data())), 
                    driver->DriverData.size(),
                    &decompressedSize, 
                    key
                );
                
                if (decompressedData && decompressedSize > 0) {
                    std::wcout << L"[+] Successfully decompressed with key 0x" << std::hex << key << std::dec << std::endl;
                    break;
                }
                
                if (decompressedData) {
                    HeapFree(GetProcessHeap(), 0, decompressedData);
                    decompressedData = nullptr;
                }
            }

            if (decompressedData && decompressedSize > 0) {
                // Write decompressed data
                outFile.write(reinterpret_cast<const char*>(decompressedData), decompressedSize);
                std::wcout << L"[+] Extracted and decompressed " << driver->DriverName 
                           << L" (" << decompressedSize << L" bytes) to " << outputPath << std::endl;
                HeapFree(GetProcessHeap(), 0, decompressedData);
            } else {
                // Fallback: write raw data (might be uncompressed)
                outFile.write(reinterpret_cast<const char*>(driver->DriverData.data()), 
                             driver->DriverData.size());
                std::wcout << L"[+] Extracted " << driver->DriverName 
                           << L" (" << driver->DriverData.size() << L" bytes) to " << outputPath << std::endl;
            }
            
            outFile.close();

            if (outFile.fail()) {
                std::wcerr << L"[-] Failed to write driver data to: " << outputPath << std::endl;
                return false;
            }

            // Now validate the extracted driver's signature
            if (!ValidateExtractedDriver(outputPath, driver.get())) {
                std::wcout << L"[!] Warning: Driver signature validation failed for " << outputPath << std::endl;
                // Don't fail extraction, just warn
            }

            return true;
        }

        const DriverInfo* DriverDataManager::GetBestDriver() {
            const DriverInfo* bestDriver = nullptr;
            int bestScore = -1;

            for (const auto& pair : drivers) {
                const auto& driver = pair.second;
                if (IsDriverSuitable(driver.get())) {
                    // Calculate comprehensive score based on multiple factors
                    int score = driver->ReliabilityScore; // Start with reliability score
                    
                    // Prefer non-blocked drivers
                    if (!driver->IsBlocked) {
                        score += 30;
                    }
                    
                    // Prefer drivers with more data (likely more complete)
                    if (driver->DriverDataSize > 50000) {
                        score += 10;
                    }
                    
                    // Known good drivers get bonus
                    if (driver->DriverId == DRIVER_ID_GDRV ||
                        driver->DriverId == DRIVER_ID_WINRING0 ||
                        driver->DriverId == DRIVER_ID_HWINFO64) {
                        score += 20;
                    }

                    // Factor in signature trust score if validated
                    if (driver->IsValidated) {
                        // Add signature trust score (scaled down)
                        score += (driver->Signature.TrustScore / 5); // Max 20 points from signature
                        
                        // Bonus for Microsoft signed drivers
                        if (driver->Signature.IsMicrosoft) {
                            score += 15;
                        }
                        
                        // Penalty for unsigned drivers
                        if (driver->Signature.Result == SIGNATURE_NOT_SIGNED) {
                            score -= 10;
                        }
                        
                        // Heavy penalty for invalid signatures
                        if (driver->Signature.Result == SIGNATURE_INVALID) {
                            score -= 25;
                        }
                    }

                    if (score > bestScore) {
                        bestScore = score;
                        bestDriver = driver.get();
                    }
                }
            }

            if (bestDriver) {
                std::wcout << L"[*] Selected best driver: " << bestDriver->DriverName 
                           << L" (Score: " << bestScore << L")" << std::endl;
                if (bestDriver->IsValidated) {
                    std::wcout << L"    Signature Trust Score: " << bestDriver->Signature.TrustScore << L"/100" << std::endl;
                }
            }

            return bestDriver;
        }

        const DriverInfo* DriverDataManager::GetDriverInfo(ULONG driverId) {
            auto it = drivers.find(driverId);
            return (it != drivers.end()) ? it->second.get() : nullptr;
        }

        std::vector<const DriverInfo*> DriverDataManager::GetAvailableDrivers() {
            std::vector<const DriverInfo*> available;
            for (const auto& pair : drivers) {
                if (IsDriverSuitable(pair.second.get())) {
                    available.push_back(pair.second.get());
                }
            }
            return available;
        }

        void DriverDataManager::ListAllDrivers() {
            std::wcout << L"\n[*] Available Drivers:" << std::endl;
            std::wcout << L"ID\tName\t\t\tSize\tBlocked\tSigned\tTrust\tFilename" << std::endl;
            std::wcout << L"--\t----\t\t\t----\t-------\t------\t-----\t--------" << std::endl;

            for (const auto& pair : drivers) {
                const auto& driver = pair.second;
                
                // Get signature status
                std::wstring signatureStatus = L"Unknown";
                std::wstring trustScore = L"N/A";
                
                if (driver->IsValidated) {
                    switch (driver->Signature.Result) {
                        case SIGNATURE_VALID:
                            signatureStatus = L"Valid";
                            trustScore = std::to_wstring(driver->Signature.TrustScore);
                            break;
                        case SIGNATURE_NOT_SIGNED:
                            signatureStatus = L"Unsigned";
                            break;
                        case SIGNATURE_INVALID:
                            signatureStatus = L"Invalid";
                            break;
                        case SIGNATURE_UNTRUSTED:
                            signatureStatus = L"Untrusted";
                            break;
                        default:
                            signatureStatus = L"Error";
                            break;
                    }
                }
                
                std::wcout << driver->DriverId << L"\t" 
                    << std::left << std::setw(20) << driver->DriverName << L"\t"
                    << driver->DriverDataSize << L"\t"
                    << (driver->IsBlocked ? L"Yes" : L"No") << L"\t"
                    << std::setw(8) << signatureStatus << L"\t"
                    << std::setw(5) << trustScore << L"\t"
                    << driver->FileName << std::endl;
            }
            std::wcout << std::endl;
        }

        bool DriverDataManager::IsDriverSuitable(const DriverInfo* driver) {
            if (!driver || driver->DriverData.empty()) {
                return false;
            }

            ULONG buildNumber = GetWindowsBuildNumber();
            
            // Check Windows version compatibility
            if (buildNumber < driver->MinWindowsBuild || buildNumber > driver->MaxWindowsBuild) {
                return false;
            }

            // Always consider drivers suitable for now - let caller decide on blocked status
            return true;
        }

        ULONG DriverDataManager::GetWindowsBuildNumber() {
            HKEY hKey;
            ULONG buildNumber = 19041; // Default to Windows 10 20H1

            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
                             L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 
                             0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                
                DWORD dataSize = sizeof(ULONG);
                DWORD type;
                
                RegQueryValueExW(hKey, L"CurrentBuildNumber", nullptr, &type, 
                               reinterpret_cast<LPBYTE>(&buildNumber), &dataSize);
                
                RegCloseKey(hKey);
            }

            return buildNumber;
        }


        PVOID DriverDataManager::DecompressDriverData(PVOID ResourcePtr, SIZE_T ResourceSize,
                                                     PSIZE_T DecompressedSize, ULONG DecryptKey) {
            // KDU-style decompression using Microsoft Delta API
            if (!ResourcePtr || ResourceSize == 0) return nullptr;

            *DecompressedSize = 0;

            // Step 1: Create temporary buffer and decrypt with XOR + rotation (KDU style)
            PVOID dataBlob = VirtualAlloc(nullptr, ResourceSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!dataBlob) return nullptr;

            memcpy(dataBlob, ResourcePtr, ResourceSize);
            
            // Apply KDU-style XOR decryption with rotation
            if (DecryptKey != 0) {
                 auto localEncodeBuffer = [](PVOID Buffer, ULONG BufferSize, ULONG Key) {
                    // Implementation must match KDU Compress.cpp EncodeBuffer exactly
                    // KDU uses byte-by-byte XOR with rotation
                    if (!Buffer || BufferSize == 0) return;
                    
                    ULONG k = Key;
                    ULONG c = BufferSize;
                    PUCHAR ptr = static_cast<PUCHAR>(Buffer);
                    
                    do {
                        *ptr ^= k;
                        k = _rotl(k, 1);
                        ptr++;
                        --c;
                    } while (c != 0);
                };
                localEncodeBuffer(dataBlob, static_cast<ULONG>(ResourceSize), DecryptKey);
            }

            // DEBUG DUMP - Full Binary
            {
                std::string dumpPath = "C:\\Users\\admin\\Documents\\decrypted_" + std::to_string(DecryptKey) + ".bin";
                std::ofstream binDump(dumpPath, std::ios::binary);
                if (binDump.is_open()) {
                     binDump.write((char*)dataBlob, ResourceSize);
                }
                
                std::ofstream txtDump("C:\\Users\\admin\\Documents\\debug_dump.txt", std::ios::app);
                if (txtDump.is_open()) {
                    txtDump << "Key: 0x" << std::hex << DecryptKey << " Size: " << std::dec << ResourceSize << std::endl;
                    unsigned char* ptr = (unsigned char*)dataBlob;
                    txtDump << "Head: " << std::hex << (int)ptr[0] << " " << (int)ptr[1] << " " << (int)ptr[2] << " " << (int)ptr[3] << std::dec << std::endl;
                }
            }
            // END DEBUG DUMP

            // Step 2: Prepare for Delta decompression
            DELTA_INPUT diSource = { 0 };  // Empty source for raw decompression
            DELTA_INPUT diDelta = { 0 };
            DELTA_OUTPUT doOutput = { 0 };

            diDelta.Editable = FALSE;
            diDelta.lpcStart = dataBlob;
            diDelta.uSize = ResourceSize;

            PVOID resultPtr = nullptr;

            // Step 3: Apply Delta decompression
            if (ApplyDeltaB(DELTA_FILE_TYPE_RAW, diSource, diDelta, &doOutput)) {
                SIZE_T decompressedSize = doOutput.uSize;
                PVOID decompressedData = doOutput.lpStart;

                // Step 4: Allocate and copy result
                resultPtr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, decompressedSize);
                if (resultPtr) {
                    memcpy(resultPtr, decompressedData, decompressedSize);
                    *DecompressedSize = decompressedSize;
                    
                    std::wcout << L"[+] Successfully decompressed " << ResourceSize 
                               << L" bytes to " << decompressedSize << L" bytes" << std::endl;
                }

                // Free Delta output
                DeltaFree(doOutput.lpStart);
            }
            else {
                // If Delta decompression fails, check if it's a valid PE (MZ)
                unsigned char* check = (unsigned char*)dataBlob;
                if (ResourceSize > 2 && check[0] == 0x4D && check[1] == 0x5A) {
                     std::wcout << L"[*] Delta failed but MZ signature found. Assuming raw PE." << std::endl;
                     resultPtr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ResourceSize);
                     if (resultPtr) {
                        memcpy(resultPtr, dataBlob, ResourceSize);
                        *DecompressedSize = ResourceSize;
                     }
                } else {
                     std::wcout << L"[-] Delta failed and no MZ signature. Decryption failed for key 0x" << std::hex << DecryptKey << std::dec << std::endl;
                     resultPtr = nullptr;
                }
            }

            // Clean up temporary buffer
            VirtualFree(dataBlob, 0, MEM_RELEASE);
            return resultPtr;
        }

        bool DriverDataManager::ValidateDriverSignature(const std::wstring& driverPath, SignatureInfo& signatureInfo) {
            // Initialize signature info
            memset(&signatureInfo, 0, sizeof(SignatureInfo));
            signatureInfo.Result = SIGNATURE_UNKNOWN;
            signatureInfo.TrustScore = 0;

            // Prepare WINTRUST_FILE_INFO structure
            WINTRUST_FILE_INFO fileInfo = { 0 };
            fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
            fileInfo.pcwszFilePath = driverPath.c_str();
            fileInfo.hFile = nullptr;
            fileInfo.pgKnownSubject = nullptr;

            // Prepare WINTRUST_DATA structure
            WINTRUST_DATA trustData = { 0 };
            trustData.cbStruct = sizeof(WINTRUST_DATA);
            trustData.pPolicyCallbackData = nullptr;
            trustData.pSIPClientData = nullptr;
            trustData.dwUIChoice = WTD_UI_NONE;
            trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
            trustData.dwUnionChoice = WTD_CHOICE_FILE;
            trustData.dwStateAction = WTD_STATEACTION_VERIFY;
            trustData.hWVTStateData = nullptr;
            trustData.pwszURLReference = nullptr;
            trustData.dwProvFlags = WTD_SAFER_FLAG;
            trustData.dwUIContext = 0;
            trustData.pFile = &fileInfo;

            // Call WinVerifyTrust
            GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            LONG result = WinVerifyTrust(nullptr, &policyGUID, &trustData);

            // Process result
            switch (result) {
                case ERROR_SUCCESS:
                    signatureInfo.Result = SIGNATURE_VALID;
                    signatureInfo.TrustScore = 80; // Base score for valid signature
                    break;
                case TRUST_E_NOSIGNATURE:
                    signatureInfo.Result = SIGNATURE_NOT_SIGNED;
                    break;
                case TRUST_E_EXPLICIT_DISTRUST:
                    signatureInfo.Result = SIGNATURE_UNTRUSTED;
                    break;
                case TRUST_E_SUBJECT_NOT_TRUSTED:
                    signatureInfo.Result = SIGNATURE_UNTRUSTED;
                    break;
                case CRYPT_E_SECURITY_SETTINGS:
                    signatureInfo.Result = SIGNATURE_INVALID;
                    break;
                default:
                    signatureInfo.Result = SIGNATURE_INVALID;
                    break;
            }

            // If signature is valid, extract certificate information
            if (signatureInfo.Result == SIGNATURE_VALID && trustData.hWVTStateData) {
                CRYPT_PROVIDER_DATA* provData = WTHelperProvDataFromStateData(trustData.hWVTStateData);
                if (provData) {
                    CRYPT_PROVIDER_SGNR* signer = WTHelperGetProvSignerFromChain(provData, 0, FALSE, 0);
                    if (signer && signer->pChainContext) {
                        PCCERT_CONTEXT certContext = signer->pChainContext->rgpChain[0]->rgpElement[0]->pCertContext;
                        if (certContext) {
                            // Extract subject name
                            DWORD subjectNameSize = CertGetNameStringW(certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
                            if (subjectNameSize > 1) {
                                std::vector<wchar_t> subjectNameBuffer(subjectNameSize);
                                CertGetNameStringW(certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, subjectNameBuffer.data(), subjectNameSize);
                                signatureInfo.SubjectName = subjectNameBuffer.data();
                            }

                            // Extract issuer name
                            DWORD issuerNameSize = CertGetNameStringW(certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nullptr, nullptr, 0);
                            if (issuerNameSize > 1) {
                                std::vector<wchar_t> issuerNameBuffer(issuerNameSize);
                                CertGetNameStringW(certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nullptr, issuerNameBuffer.data(), issuerNameSize);
                                signatureInfo.IssuerName = issuerNameBuffer.data();
                            }

                            // Check if it's Microsoft signed
                            signatureInfo.IsMicrosoft = (signatureInfo.SubjectName.find(L"Microsoft") != std::wstring::npos ||
                                                       signatureInfo.IssuerName.find(L"Microsoft") != std::wstring::npos);

                            // Calculate enhanced trust score
                            signatureInfo.TrustScore = CalculateTrustScore(signatureInfo);
                        }
                    }
                }
            }

            // Clean up WinVerifyTrust state
            if (trustData.hWVTStateData) {
                trustData.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(nullptr, &policyGUID, &trustData);
            }

            return signatureInfo.Result == SIGNATURE_VALID;
        }

        bool DriverDataManager::ValidateExtractedDriver(const std::wstring& driverPath, DriverInfo* driverInfo) {
            if (!driverInfo) return false;

            std::wcout << L"[*] Validating digital signature for " << driverPath << std::endl;

            // Validate the driver signature
            SignatureInfo signatureInfo;
            bool isValid = ValidateDriverSignature(driverPath, signatureInfo);

            // Store signature information
            driverInfo->Signature = signatureInfo;
            driverInfo->IsValidated = true;

            // Report validation results
            switch (signatureInfo.Result) {
                case SIGNATURE_VALID:
                    std::wcout << L"[+] Digital signature is VALID" << std::endl;
                    if (!signatureInfo.SubjectName.empty()) {
                        std::wcout << L"    Subject: " << signatureInfo.SubjectName << std::endl;
                    }
                    if (!signatureInfo.IssuerName.empty()) {
                        std::wcout << L"    Issuer: " << signatureInfo.IssuerName << std::endl;
                    }
                    std::wcout << L"    Trust Score: " << signatureInfo.TrustScore << L"/100" << std::endl;
                    if (signatureInfo.IsMicrosoft) {
                        std::wcout << L"    [+] Microsoft-signed driver" << std::endl;
                    }
                    break;
                case SIGNATURE_NOT_SIGNED:
                    std::wcout << L"[!] Driver is NOT SIGNED" << std::endl;
                    break;
                case SIGNATURE_INVALID:
                    std::wcout << L"[-] Digital signature is INVALID" << std::endl;
                    break;
                case SIGNATURE_UNTRUSTED:
                    std::wcout << L"[!] Digital signature is UNTRUSTED" << std::endl;
                    break;
                default:
                    std::wcout << L"[?] Digital signature validation result: " << signatureInfo.Result << std::endl;
                    break;
            }

            return isValid;
        }

        int DriverDataManager::CalculateTrustScore(const SignatureInfo& signatureInfo) {
            int score = 0;

            // Base score for valid signature
            if (signatureInfo.Result == SIGNATURE_VALID) {
                score = 50;
            }

            // Microsoft signed gets high bonus
            if (signatureInfo.IsMicrosoft) {
                score += 40;
            }

            // Known good signers get bonus
            if (IsKnownGoodSigner(signatureInfo.SubjectName)) {
                score += 20;
            }

            // Hardware vendor signatures get moderate bonus
            if (signatureInfo.SubjectName.find(L"NVIDIA") != std::wstring::npos ||
                signatureInfo.SubjectName.find(L"Intel") != std::wstring::npos ||
                signatureInfo.SubjectName.find(L"AMD") != std::wstring::npos ||
                signatureInfo.SubjectName.find(L"ASUS") != std::wstring::npos ||
                signatureInfo.SubjectName.find(L"MSI") != std::wstring::npos ||
                signatureInfo.SubjectName.find(L"GIGABYTE") != std::wstring::npos) {
                score += 15;
            }

            // Timestamp adds reliability
            if (signatureInfo.HasTimestamp) {
                score += 10;
            }

            // Cap at 100
            return (score > 100) ? 100 : score;
        }

        bool DriverDataManager::IsKnownGoodSigner(const std::wstring& subjectName) {
            // List of known legitimate hardware/software vendors
            std::vector<std::wstring> knownGoodSigners = {
                L"Microsoft Corporation",
                L"Microsoft Windows Hardware Compatibility Publisher",
                L"NVIDIA Corporation",
                L"Intel Corporation",
                L"Advanced Micro Devices",
                L"ASUSTeK Computer Inc.",
                L"Micro-Star International",
                L"GIGA-BYTE TECHNOLOGY CO., LTD.",
                L"Dell Inc."
            };

            for (const auto& goodSigner : knownGoodSigners) {
                if (subjectName.find(goodSigner) != std::wstring::npos) {
                    return true;
                }
            }

            return false;
        }

    } // namespace Resources
} // namespace KernelMode

