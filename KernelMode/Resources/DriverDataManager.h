/**
 * @file DriverDataManager.h
 * @author Gregory King  
 * @date August 14, 2025
 * @brief This file contains the DriverDataManager class for handling embedded driver resources.
 *
 * Manages driver .bin files using KDU-style resource system with support for the complete
 * collection of vulnerable drivers found in data/ and Drv/ directories.
 */

#pragma once

#define NOMINMAX  // Prevent Windows.h from defining min/max macros

#include <Windows.h>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <msdelta.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <mscat.h>
#include "resource.h"

#pragma comment(lib, "msdelta.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#include <algorithm>
#include <iostream>
#include <fstream>

namespace KernelMode {
    namespace Resources {

        // Driver constants matching DriverDataManager.cpp usage
        constexpr ULONG DRIVER_ID_RTCORE = 0;
        constexpr ULONG DRIVER_ID_GDRV = 2;
        constexpr ULONG DRIVER_ID_DBUTIL_2_3 = 55; // Maps to DBUtil_2_3.sys
        constexpr ULONG DRIVER_ID_PROCEXP = 3;
        constexpr ULONG DRIVER_ID_KPH = 4;
        constexpr ULONG DRIVER_ID_INTEL_NAL = 5;
        // Extended IDs
        constexpr ULONG DRIVER_ID_WINIO = 34; // KDU 34?
        constexpr ULONG DRIVER_ID_ECHO_DRV = 35;
        constexpr ULONG DRIVER_ID_WINRING0 = 14;
        constexpr ULONG DRIVER_ID_ASRDRV = 62; 
        constexpr ULONG DRIVER_ID_MIMIDRV = 70; // Arbitrary
        constexpr ULONG DRIVER_ID_NEACSAFE64 = 80;
        constexpr ULONG DRIVER_ID_AIDA64 = 13;
        constexpr ULONG DRIVER_ID_HWINFO64 = 30;

        // Aliases
        constexpr ULONG DRIVER_ID_RTCORE64 = DRIVER_ID_RTCORE;
        constexpr ULONG DRIVER_ID_DBUTIL = DRIVER_ID_DBUTIL_2_3;
        constexpr ULONG DRIVER_ID_KPROCESSHACKER = DRIVER_ID_KPH;

        constexpr ULONG DRIVER_ID_RTCORE_EXTERNAL = 100;
        constexpr ULONG DRIVER_ID_GDRV_EXTERNAL = 101;
        constexpr ULONG DRIVER_ID_DBUTIL_EXTERNAL = 102;
        
        // Resource Keys for decryption (0 for no encryption/default)
        // KDU decompression keys - these are the actual keys from KDU source
        constexpr ULONG PROVIDER_RES_KEYS[] = { 
            0xF62E6CE0,  // Verified key for Tanikaze gdrv.bin
            0x70E0DD63,  // Primary KDU key
            0,           // No encryption (fallback)
            0x3284C2D,   // Alternative key 1
            0x7D83D2E,   // Alternative key 2
            0x6BA1A8E    // Alternative key 3
        };
        
        /**
         * @enum SignatureValidationResult
         * @brief Results of digital signature validation
         */
        enum SignatureValidationResult {
            SIGNATURE_UNKNOWN = 0,
            SIGNATURE_VALID = 1,
            SIGNATURE_INVALID = 2,
            SIGNATURE_UNTRUSTED = 3,
            SIGNATURE_REVOKED = 4,
            SIGNATURE_EXPIRED = 5,
            SIGNATURE_NOT_SIGNED = 6
        };

        /**
         * @struct SignatureInfo
         * @brief Digital signature information for drivers
         */
        struct SignatureInfo {
            SignatureValidationResult Result;
            std::wstring SubjectName;
            std::wstring IssuerName;
            std::wstring SerialNumber;
            FILETIME SigningTime;
            FILETIME TimestampTime;
            bool HasTimestamp;
            bool IsWHQL;
            bool IsMicrosoft;
            int TrustScore;  // 0-100, higher = more trustworthy
        };


        /**
         * @struct DriverInfo
         * @brief Contains information about a vulnerable driver.
         */
        struct DriverInfo {
            ULONG DriverId;
            std::wstring DriverName;
            std::wstring FileName;
            std::vector<BYTE> DriverData;
            SIZE_T DriverDataSize;  // Size of the driver data
            ULONG MinWindowsBuild;
            ULONG MaxWindowsBuild;
            bool IsBlocked;
            std::wstring SourcePath;
            std::wstring CVE;
            std::wstring Description;
            int ReliabilityScore;  // Higher = more reliable
            SignatureInfo Signature;  // Digital signature validation results
            bool ValidationEnabled = true;
            bool IsValidated = false;
        };

        // KDU Flags
        #define KDUPROV_FLAGS_NONE                  0x00000000
        #define KDUPROV_FLAGS_SUPPORT_HVCI          0x00000001
        #define KDUPROV_FLAGS_SIGNATURE_WHQL        0x00000002 
        #define KDUPROV_FLAGS_IGNORE_CHECKSUM       0x00000004
        #define KDUPROV_FLAGS_NO_FORCED_SD          0x00000008
        #define KDUPROV_FLAGS_NO_UNLOAD_SUP         0x00000010
        #define KDUPROV_FLAGS_PML4_FROM_LOWSTUB     0x00000020
        #define KDUPROV_FLAGS_NO_VICTIM             0x00000040
        #define KDUPROV_FLAGS_PHYSICAL_BRUTE_FORCE  0x00000080
        #define KDUPROV_FLAGS_PREFER_PHYSICAL       0x00000100
        #define KDUPROV_FLAGS_PREFER_VIRTUAL        0x00000200
        #define KDUPROV_FLAGS_COMPANION_REQUIRED    0x00000400
        #define KDUPROV_FLAGS_USE_SYMBOLS           0x00000800
        #define KDUPROV_FLAGS_OPENPROCESS_SUPPORTED 0x00001000
        #define KDUPROV_FLAGS_FS_FILTER            0x00002000

        typedef enum _KDU_SOURCEBASE {
            SourceBaseNone = 0,
            SourceBaseWinIo,
            SourceBaseWinRing0,
            SourceBasePhyMem,
            SourceBaseMapMem,
            SourceBaseRWEverything,
            SourceBaseMax
        } KDU_SOURCEBASE;

        typedef struct _KDU_DB_ENTRY {
            ULONG MinNtBuildNumberSupport;
            ULONG MaxNtBuildNumberSupport;
            ULONG ResourceId;
            ULONG ProviderId;
            ULONG VictimId;
            KDU_SOURCEBASE DrvSourceBase;
            union {
                ULONG Flags;
                struct {
                    ULONG SupportHVCI : 1;
                    ULONG SignatureWHQL : 1;
                    ULONG IgnoreChecksum : 1;
                    ULONG NoForcedSD : 1;
                    ULONG NoUnloadSupported : 1;
                    ULONG PML4FromLowStub : 1;
                    ULONG NoVictim : 1;
                    ULONG PhysMemoryBruteForce : 1;
                    ULONG PreferPhysical : 1;
                    ULONG PreferVirtual : 1;
                    ULONG CompanionRequired : 1;
                    ULONG UseSymbols : 1;
                    ULONG OpenProcessSupported : 1;
                    ULONG FsFilter : 1;
                    ULONG Reserved : 18;
                };
            };
            ULONG SupportedShellFlags;
            LPWSTR Desciption;
            LPWSTR DriverName; //only file name, e.g. PROCEXP
            union {
                LPWSTR DeviceName; //device name, e.g. PROCEXP152
                LPWSTR PortName;
            };
            LPWSTR SignerName;
        } KDU_DB_ENTRY, * PKDU_DB_ENTRY;

        typedef struct _KDU_DB {
            ULONG NumberOfEntries;
            KDU_DB_ENTRY* Entries;
        } KDU_DB, * PKDU_DB;

        /**
         * @class DriverDataManager  
         * @brief Manages driver resources in KDU style with comprehensive driver support.
         */
        class DriverDataManager {
        public:
            static DriverDataManager& GetInstance();
            bool Initialize();
            bool LoadTanikaze(const std::wstring& dllPath = L"drv64.dll");
            bool ExtractDriver(ULONG driverId, const std::wstring& outputPath);
            std::wstring GetDriverFamily(ULONG driverId);
            bool ValidateDriverSignature(const std::wstring& driverPath, SignatureInfo& signatureInfo);
            const DriverInfo* GetBestDriver();
            const DriverInfo* GetDriverInfo(ULONG driverId);
            std::vector<const DriverInfo*> GetAvailableDrivers();
            void ListAllDrivers();

        private:
            DriverDataManager() = default;
            ~DriverDataManager();
            DriverDataManager(const DriverDataManager&) = delete;
            DriverDataManager& operator=(const DriverDataManager&) = delete;

            bool IsDriverSuitable(const DriverInfo* driver);


            // Helper methods
            ULONG GetWindowsBuildNumber();
            USHORT CalculatePartialChecksum(ULONG PartialSum, PUSHORT Source, ULONG Length);
            BOOLEAN VerifyPEChecksum(PVOID BaseAddress, ULONG FileLength, PULONG HeaderChecksum, PULONG CalculatedChecksum);
            PVOID DecompressDriverData(PVOID ResourcePtr, SIZE_T ResourceSize, 
                                     PSIZE_T DecompressedSize, ULONG DecryptKey);
            bool ValidateExtractedDriver(const std::wstring& driverPath, DriverInfo* driverInfo);
            int CalculateTrustScore(const SignatureInfo& signatureInfo);
            bool IsKnownGoodSigner(const std::wstring& subjectName);
            
            HMODULE hTanikaze = NULL; // Handle to the loaded Tanikaze DLL
            
            std::map<ULONG, std::unique_ptr<DriverInfo>> drivers;
            bool initialized = false;
        };

    } // namespace Resources
} // namespace KernelMode
