// ThreatOne App - AssetViewModel Implementation

#include "app/viewmodels/AssetViewModel.h"
#include <string>
#include <vector>

namespace ThreatOne::App {

#ifdef ENABLE_QT_BUILD

AssetViewModel::AssetViewModel(QObject* parent)
    : QObject(parent)
    , logger_(ThreatOne::Core::Logger::instance().getModuleLogger("AssetViewModel")) {
}

AssetViewModel::~AssetViewModel() = default;

int AssetViewModel::totalAssets() const { return totalAssets_; }
int AssetViewModel::healthyCount() const { return healthyCount_; }
int AssetViewModel::atRiskCount() const { return atRiskCount_; }

QVariantList AssetViewModel::getAssetDetail(const QString& /*id*/) {
    return {};
}

QVariantList AssetViewModel::getSoftwareInventory(const QString& /*id*/) {
    return {};
}

QVariantList AssetViewModel::getVulnerabilities(const QString& /*id*/) {
    return {};
}

QVariantList AssetViewModel::getEvents(const QString& /*id*/) {
    return {};
}

void AssetViewModel::scanAsset(const QString& /*id*/) {
    emit dataUpdated();
}

#else // !ENABLE_QT_BUILD

AssetViewModel::AssetViewModel()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("AssetViewModel")) {
}

AssetViewModel::~AssetViewModel() = default;

int AssetViewModel::totalAssets() const { return totalAssets_; }
int AssetViewModel::healthyCount() const { return healthyCount_; }
int AssetViewModel::atRiskCount() const { return atRiskCount_; }

std::vector<std::string> AssetViewModel::getAssetDetail(const std::string& /*id*/) {
    return {};
}

std::vector<std::string> AssetViewModel::getSoftwareInventory(const std::string& /*id*/) {
    return {};
}

std::vector<std::string> AssetViewModel::getVulnerabilities(const std::string& /*id*/) {
    return {};
}

std::vector<std::string> AssetViewModel::getEvents(const std::string& /*id*/) {
    return {};
}

void AssetViewModel::scanAsset(const std::string& /*id*/) {}

#endif // ENABLE_QT_BUILD

} // namespace ThreatOne::App
