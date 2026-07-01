#include "licensing/LicenseManager.h"

namespace ThreatOne::Licensing {

LicenseManager::LicenseManager()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("LicenseManager")) {
    logger_.info("LicenseManager initialized (stub)");
}

bool LicenseManager::activate(const std::string& key) {
    logger_.info("activate called: {}", key);
    return true;
}

bool LicenseManager::deactivate() {
    logger_.info("deactivate called");
    return true;
}

bool LicenseManager::validate() {
    logger_.info("validate called");
    return true;
}

LicenseInfo LicenseManager::getLicenseInfo() {
    logger_.info("getLicenseInfo called");
    return {"LIC-001", "", LicenseType::Free, "", true, 1};
}

std::vector<FeatureInfo> LicenseManager::getFeatures() {
    logger_.info("getFeatures called");
    return {
        {"basic_scan", "Basic file scanning", LicenseType::Free, true},
        {"advanced_ai", "AI-powered threat detection", LicenseType::Enterprise, false}
    };
}

bool LicenseManager::isFeatureEnabled(const std::string& feature) {
    logger_.info("isFeatureEnabled called: {}", feature);
    return true;
}

} // namespace ThreatOne::Licensing
