#pragma once

#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>
#include <cstdint>

namespace ThreatOne::Cloud {

enum class CloudAssetType {
    Compute,
    Storage,
    Networking,
    IAM,
    Database,
    Container
};

enum class CloudProvider {
    AWS,
    Azure,
    GCP,
    OnPremise
};

struct CloudAsset {
    std::string id;
    std::string name;
    CloudAssetType type = CloudAssetType::Compute;
    CloudProvider provider = CloudProvider::AWS;
    std::string region;
    std::string accountId;
    std::string status;
    std::string discoveredAt;
    std::vector<std::string> tags;
    uint64_t costPerMonth = 0;  // in cents
};

struct DiscoverySummary {
    int totalAssets = 0;
    int computeCount = 0;
    int storageCount = 0;
    int networkingCount = 0;
    int iamCount = 0;
    int databaseCount = 0;
    int containerCount = 0;
};

class CloudAssetDiscovery {
public:
    CloudAssetDiscovery();
    ~CloudAssetDiscovery() = default;

    // Asset registration and discovery
    std::string registerAsset(const CloudAsset& asset);
    bool removeAsset(const std::string& assetId);
    [[nodiscard]] CloudAsset getAsset(const std::string& assetId) const;

    // Queries
    [[nodiscard]] std::vector<CloudAsset> getAssets() const;
    [[nodiscard]] std::vector<CloudAsset> getAssetsByType(CloudAssetType type) const;
    [[nodiscard]] std::vector<CloudAsset> getAssetsByProvider(CloudProvider provider) const;
    [[nodiscard]] std::vector<CloudAsset> getAssetsByRegion(const std::string& region) const;
    [[nodiscard]] std::vector<CloudAsset> searchAssets(const std::string& query) const;

    // Discovery summary
    [[nodiscard]] DiscoverySummary getSummary() const;

    // Cost tracking
    [[nodiscard]] uint64_t getTotalMonthlyCost() const;
    [[nodiscard]] uint64_t getCostByProvider(CloudProvider provider) const;

    // Metrics
    [[nodiscard]] size_t getAssetCount() const;

private:
    std::string generateAssetId();

    mutable std::mutex mutex_;
    std::map<std::string, CloudAsset> assets_;
    int nextAssetId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Cloud
