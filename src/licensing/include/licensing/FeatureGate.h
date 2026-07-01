#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <optional>

#include "licensing/ILicenseManager.h"

namespace ThreatOne::Licensing {

struct FeatureDefinition {
    std::string name;
    std::string description;
    LicenseType requiredTier = LicenseType::Free;
    bool enabled = false;
};

struct DegradationInfo {
    std::string featureName;
    std::string message;
    LicenseType requiredTier;
    LicenseType currentTier;
};

class FeatureGate {
public:
    FeatureGate();
    ~FeatureGate() = default;

    // Register a feature with its required tier
    void registerFeature(const std::string& name, LicenseType requiredTier,
                         const std::string& description = "");

    // Remove a registered feature
    bool unregisterFeature(const std::string& name);

    // Set the current active license tier
    void setCurrentTier(LicenseType tier);

    // Get the current license tier
    [[nodiscard]] LicenseType getCurrentTier() const;

    // Check if a feature is enabled at the current tier
    [[nodiscard]] bool isEnabled(const std::string& featureName) const;

    // Get the required tier for a feature
    [[nodiscard]] std::optional<LicenseType> getRequiredTier(const std::string& featureName) const;

    // Get all registered features
    [[nodiscard]] std::vector<FeatureDefinition> getAllFeatures() const;

    // Get features available at current tier
    [[nodiscard]] std::vector<FeatureDefinition> getEnabledFeatures() const;

    // Get features NOT available at current tier
    [[nodiscard]] std::vector<FeatureDefinition> getDisabledFeatures() const;

    // Graceful degradation: get info about why a feature is unavailable
    [[nodiscard]] std::optional<DegradationInfo> getDegradationInfo(const std::string& featureName) const;

    // Set degradation callback for when a disabled feature is accessed
    using DegradationCallback = std::function<void(const DegradationInfo&)>;
    void setDegradationCallback(DegradationCallback callback);

    // Track feature usage (returns true if feature was enabled and access counted)
    bool trackUsage(const std::string& featureName);

    // Get usage count for a feature
    [[nodiscard]] int getUsageCount(const std::string& featureName) const;

    // Check if a tier meets or exceeds the requirement
    [[nodiscard]] static bool tierMeetsRequirement(LicenseType current, LicenseType required);

private:
    LicenseType currentTier_ = LicenseType::Free;
    std::unordered_map<std::string, FeatureDefinition> features_;
    std::unordered_map<std::string, int> usageCounts_;
    DegradationCallback degradationCallback_;
};

} // namespace ThreatOne::Licensing
