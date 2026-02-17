#include "IProvider.h"
#include "Resources/DriverDataManager.h"

namespace KernelMode {
    namespace Providers {

        bool IProvider::ExtractDriverFromResources(ULONG driverId, const std::wstring& outputPath) {
            return KernelMode::Resources::DriverDataManager::GetInstance().ExtractDriver(driverId, outputPath);
        }

    }
}
