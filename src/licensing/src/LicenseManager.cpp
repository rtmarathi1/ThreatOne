#include "licensing/LicenseManager.h"

#include <ctime>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <string>
#include <vector>

namespace ThreatOne::Licensing {

LicenseManager::LicenseManager()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("LicenseManager")) {
    logger_.info("LicenseManager initialized");

    // Register default features
    featureGate_.registerFeature("basic_scan", LicenseType::Free, "Basic file scanning");
    featureGate_.registerFeature("scheduled_scan", LicenseType::Free, "Scheduled scanning");
    featureGate_.registerFeature("advanced_ai", LicenseType::Professional, "AI-powered threat detection");
    featureGate_.registerFeature("edr", LicenseType::Professional, "Endpoint detection and response");
    featureGate_.registerFeature("fleet_management", LicenseType::Enterprise, "Fleet management");
    featureGate_.registerFeature("sso", LicenseType::Enterprise, "Single sign-on integration");
    featureGate_.registerFeature("custom_rules", LicenseType::Enterprise, "Custom detection rules");
    featureGate_.registerFeature("unlimited_endpoints", LicenseType::Ultimate, "Unlimited endpoint support");
}

bool LicenseManager::activate(const std::string& key) {
    logger_.info("Activating license key");

    auto result = validator_.validate(key);
    if (!result.valid) {
        logger_.warn("License activation failed: {}", result.reason);
        return false;
    }

    // Parse the key to get tier info
    auto parsedKey = validator_.parseKey(key);
    if (!parsedKey.has_value()) {
        return false;
    }

    currentLicense_.key = key;
    currentLicense_.type = parsedKey->tier;
    currentLicense_.expiresAt = result.expiresAt;
    currentLicense_.active = true;
    currentLicense_.maxEndpoints = result.seatsAllowed;

    // Check grace period status
    if (result.reason.find("grace period") != std::string::npos) {
        inGracePeriod_ = true;
    } else {
        inGracePeriod_ = false;
    }

    // Calculate remaining days
    if (!result.expiresAt.empty()) {
        std::tm tm = {};
        std::istringstream iss(result.expiresAt);
        iss >> std::get_time(&tm, "%Y-%m-%d");
        if (!iss.fail()) {
            auto expiry = std::mktime(&tm);
            auto now = std::time(nullptr);
            double diff = std::difftime(expiry, now);
            remainingDays_ = static_cast<int>(std::ceil(diff / 86400.0));
            if (remainingDays_ < 0 && inGracePeriod_) {
                remainingDays_ = result.gracePeriodDays + remainingDays_;
                if (remainingDays_ < 0) remainingDays_ = 0;
            }
        }
    }

    // Update feature gate with new tier
    featureGate_.setCurrentTier(parsedKey->tier);
    activated_ = true;

    logger_.info("License activated successfully, tier: {}", static_cast<int>(parsedKey->tier));
    return true;
}

bool LicenseManager::deactivate() {
    logger_.info("Deactivating license");
    currentLicense_ = LicenseInfo{};
    activated_ = false;
    inGracePeriod_ = false;
    remainingDays_ = 0;
    featureGate_.setCurrentTier(LicenseType::Free);
    return true;
}

bool LicenseManager::validate() {
    if (!activated_ || currentLicense_.key.empty()) {
        return false;
    }
    auto result = validator_.validate(currentLicense_.key);
    return result.valid;
}

LicenseInfo LicenseManager::getLicenseInfo() {
    return currentLicense_;
}

std::vector<FeatureInfo> LicenseManager::getFeatures() {
    auto allFeatures = featureGate_.getAllFeatures();
    std::vector<FeatureInfo> result;
    result.reserve(allFeatures.size());
    for (const auto& def : allFeatures) {
        FeatureInfo info;
        info.name = def.name;
        info.description = def.description;
        info.requiredLicense = def.requiredTier;
        info.enabled = def.enabled;
        result.push_back(info);
    }
    return result;
}

bool LicenseManager::isFeatureEnabled(const std::string& feature) {
    return featureGate_.isEnabled(feature);
}

ValidationResult LicenseManager::validateKey(const std::string& key) const {
    return validator_.validate(key);
}

std::vector<FeatureDefinition> LicenseManager::getEntitlements() const {
    return featureGate_.getEnabledFeatures();
}

int LicenseManager::getSeatCount() const {
    return currentLicense_.maxEndpoints;
}

int LicenseManager::getRemainingDays() const {
    return remainingDays_;
}

bool LicenseManager::isInGracePeriod() const {
    return inGracePeriod_;
}

FeatureGate& LicenseManager::getFeatureGate() {
    return featureGate_;
}

const FeatureGate& LicenseManager::getFeatureGate() const {
    return featureGate_;
}

const LicenseValidator& LicenseManager::getValidator() const {
    return validator_;
}

} // namespace ThreatOne::Licensing
