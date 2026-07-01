#pragma once

#include <string>
#include <vector>

namespace ThreatOne::Licensing {

enum class LicenseType {
    Free,
    Professional,
    Enterprise,
    Ultimate
};

struct LicenseInfo {
    std::string id;
    std::string key;
    LicenseType type = LicenseType::Free;
    std::string expiresAt;
    bool active = false;
    int maxEndpoints = 1;
};

struct FeatureInfo {
    std::string name;
    std::string description;
    LicenseType requiredLicense;
    bool enabled = false;
};

class ILicenseManager {
public:
    virtual ~ILicenseManager() = default;

    virtual bool activate(const std::string& key) = 0;
    virtual bool deactivate() = 0;
    virtual bool validate() = 0;
    virtual LicenseInfo getLicenseInfo() = 0;
    virtual std::vector<FeatureInfo> getFeatures() = 0;
    virtual bool isFeatureEnabled(const std::string& feature) = 0;
};

} // namespace ThreatOne::Licensing
