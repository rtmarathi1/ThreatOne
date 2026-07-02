#include "cloud/CloudAssetDiscovery.h"

#include <algorithm>
#include <cctype>

namespace ThreatOne::Cloud {

CloudAssetDiscovery::CloudAssetDiscovery()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("CloudAssetDiscovery")) {
    logger_.info("CloudAssetDiscovery initialized");
}

std::string CloudAssetDiscovery::generateAssetId() {
    return "ASSET-" + std::to_string(nextAssetId_++);
}

std::string CloudAssetDiscovery::registerAsset(const CloudAsset& asset) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = asset.id.empty() ? generateAssetId() : asset.id;
    CloudAsset stored = asset;
    stored.id = id;
    stored.discoveredAt = "now";
    assets_[id] = stored;

    logger_.info("Registered cloud asset: id={}, name={}, type={}", id, asset.name, static_cast<int>(asset.type));
    return id;
}

bool CloudAssetDiscovery::removeAsset(const std::string& assetId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = assets_.find(assetId);
    if (it == assets_.end()) {
        logger_.warn("removeAsset: asset {} not found", assetId);
        return false;
    }

    assets_.erase(it);
    logger_.info("Removed cloud asset: {}", assetId);
    return true;
}

CloudAsset CloudAssetDiscovery::getAsset(const std::string& assetId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = assets_.find(assetId);
    if (it == assets_.end()) {
        return {};
    }
    return it->second;
}

std::vector<CloudAsset> CloudAssetDiscovery::getAssets() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<CloudAsset> result;
    result.reserve(assets_.size());
    for (const auto& [id, asset] : assets_) {
        result.push_back(asset);
    }
    return result;
}

std::vector<CloudAsset> CloudAssetDiscovery::getAssetsByType(CloudAssetType type) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<CloudAsset> result;
    for (const auto& [id, asset] : assets_) {
        if (asset.type == type) {
            result.push_back(asset);
        }
    }
    return result;
}

std::vector<CloudAsset> CloudAssetDiscovery::getAssetsByProvider(CloudProvider provider) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<CloudAsset> result;
    for (const auto& [id, asset] : assets_) {
        if (asset.provider == provider) {
            result.push_back(asset);
        }
    }
    return result;
}

std::vector<CloudAsset> CloudAssetDiscovery::getAssetsByRegion(const std::string& region) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<CloudAsset> result;
    for (const auto& [id, asset] : assets_) {
        if (asset.region == region) {
            result.push_back(asset);
        }
    }
    return result;
}

std::vector<CloudAsset> CloudAssetDiscovery::searchAssets(const std::string& query) const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (query.empty()) {
        std::vector<CloudAsset> result;
        result.reserve(assets_.size());
        for (const auto& [id, asset] : assets_) {
            result.push_back(asset);
        }
        return result;
    }

    std::string lowerQuery = query;
    std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(),
        [](char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); });

    std::vector<CloudAsset> result;
    for (const auto& [id, asset] : assets_) {
        std::string lowerName = asset.name;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(),
            [](char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); });

        if (lowerName.find(lowerQuery) != std::string::npos) {
            result.push_back(asset);
            continue;
        }

        // Check tags
        for (const auto& tag : asset.tags) {
            std::string lowerTag = tag;
            std::transform(lowerTag.begin(), lowerTag.end(), lowerTag.begin(),
                [](char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); });
            if (lowerTag.find(lowerQuery) != std::string::npos) {
                result.push_back(asset);
                break;
            }
        }
    }
    return result;
}

DiscoverySummary CloudAssetDiscovery::getSummary() const {
    std::lock_guard<std::mutex> lock(mutex_);

    DiscoverySummary summary;
    summary.totalAssets = static_cast<int>(assets_.size());

    for (const auto& [id, asset] : assets_) {
        switch (asset.type) {
            case CloudAssetType::Compute:    summary.computeCount++; break;
            case CloudAssetType::Storage:    summary.storageCount++; break;
            case CloudAssetType::Networking: summary.networkingCount++; break;
            case CloudAssetType::IAM:        summary.iamCount++; break;
            case CloudAssetType::Database:   summary.databaseCount++; break;
            case CloudAssetType::Container:  summary.containerCount++; break;
        }
    }
    return summary;
}

uint64_t CloudAssetDiscovery::getTotalMonthlyCost() const {
    std::lock_guard<std::mutex> lock(mutex_);

    uint64_t total = 0;
    for (const auto& [id, asset] : assets_) {
        total += asset.costPerMonth;
    }
    return total;
}

uint64_t CloudAssetDiscovery::getCostByProvider(CloudProvider provider) const {
    std::lock_guard<std::mutex> lock(mutex_);

    uint64_t total = 0;
    for (const auto& [id, asset] : assets_) {
        if (asset.provider == provider) {
            total += asset.costPerMonth;
        }
    }
    return total;
}

size_t CloudAssetDiscovery::getAssetCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return assets_.size();
}

} // namespace ThreatOne::Cloud
