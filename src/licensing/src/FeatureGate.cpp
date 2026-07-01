#include "licensing/FeatureGate.h"

namespace ThreatOne::Licensing {

FeatureGate::FeatureGate()
    : currentTier_(LicenseType::Free) {
}

void FeatureGate::registerFeature(const std::string& name, LicenseType requiredTier,
                                   const std::string& description) {
    FeatureDefinition def;
    def.name = name;
    def.description = description;
    def.requiredTier = requiredTier;
    def.enabled = tierMeetsRequirement(currentTier_, requiredTier);
    features_[name] = def;
}

bool FeatureGate::unregisterFeature(const std::string& name) {
    auto it = features_.find(name);
    if (it == features_.end()) {
        return false;
    }
    features_.erase(it);
    usageCounts_.erase(name);
    return true;
}

void FeatureGate::setCurrentTier(LicenseType tier) {
    currentTier_ = tier;
    // Update enabled status for all features
    for (auto& [name, def] : features_) {
        def.enabled = tierMeetsRequirement(currentTier_, def.requiredTier);
    }
}

LicenseType FeatureGate::getCurrentTier() const {
    return currentTier_;
}

bool FeatureGate::isEnabled(const std::string& featureName) const {
    auto it = features_.find(featureName);
    if (it == features_.end()) {
        return false;  // Unknown feature is disabled
    }
    return it->second.enabled;
}

std::optional<LicenseType> FeatureGate::getRequiredTier(const std::string& featureName) const {
    auto it = features_.find(featureName);
    if (it == features_.end()) {
        return std::nullopt;
    }
    return it->second.requiredTier;
}

std::vector<FeatureDefinition> FeatureGate::getAllFeatures() const {
    std::vector<FeatureDefinition> result;
    result.reserve(features_.size());
    for (const auto& [name, def] : features_) {
        result.push_back(def);
    }
    return result;
}

std::vector<FeatureDefinition> FeatureGate::getEnabledFeatures() const {
    std::vector<FeatureDefinition> result;
    for (const auto& [name, def] : features_) {
        if (def.enabled) {
            result.push_back(def);
        }
    }
    return result;
}

std::vector<FeatureDefinition> FeatureGate::getDisabledFeatures() const {
    std::vector<FeatureDefinition> result;
    for (const auto& [name, def] : features_) {
        if (!def.enabled) {
            result.push_back(def);
        }
    }
    return result;
}

std::optional<DegradationInfo> FeatureGate::getDegradationInfo(const std::string& featureName) const {
    auto it = features_.find(featureName);
    if (it == features_.end()) {
        return std::nullopt;
    }

    if (it->second.enabled) {
        return std::nullopt;  // Feature is enabled, no degradation
    }

    DegradationInfo info;
    info.featureName = featureName;
    info.requiredTier = it->second.requiredTier;
    info.currentTier = currentTier_;
    info.message = "Feature '" + featureName + "' requires a higher license tier";

    // Notify via callback if set
    if (degradationCallback_) {
        degradationCallback_(info);
    }

    return info;
}

void FeatureGate::setDegradationCallback(DegradationCallback callback) {
    degradationCallback_ = std::move(callback);
}

bool FeatureGate::trackUsage(const std::string& featureName) {
    if (!isEnabled(featureName)) {
        return false;
    }
    usageCounts_[featureName]++;
    return true;
}

int FeatureGate::getUsageCount(const std::string& featureName) const {
    auto it = usageCounts_.find(featureName);
    if (it == usageCounts_.end()) {
        return 0;
    }
    return it->second;
}

bool FeatureGate::tierMeetsRequirement(LicenseType current, LicenseType required) {
    // Tier ordering: Free < Professional < Enterprise < Ultimate
    return static_cast<int>(current) >= static_cast<int>(required);
}

} // namespace ThreatOne::Licensing
