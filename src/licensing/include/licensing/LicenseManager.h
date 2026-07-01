#pragma once

#include "licensing/ILicenseManager.h"
#include "core/Logger.h"

namespace ThreatOne::Licensing {

class LicenseManager : public ILicenseManager {
public:
    LicenseManager();
    ~LicenseManager() override = default;

    bool activate(const std::string& key) override;
    bool deactivate() override;
    bool validate() override;
    LicenseInfo getLicenseInfo() override;
    std::vector<FeatureInfo> getFeatures() override;
    bool isFeatureEnabled(const std::string& feature) override;

private:
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Licensing
