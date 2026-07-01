#pragma once

#include "licensing/ILicenseManager.h"
#include "licensing/LicenseValidator.h"
#include "licensing/FeatureGate.h"
#include "core/Logger.h"

#include <memory>

namespace ThreatOne::Licensing {

class LicenseManager : public ILicenseManager {
public:
    LicenseManager();
    ~LicenseManager() override = default;

    // ILicenseManager interface
    bool activate(const std::string& key) override;
    bool deactivate() override;
    bool validate() override;
    LicenseInfo getLicenseInfo() override;
    std::vector<FeatureInfo> getFeatures() override;
    bool isFeatureEnabled(const std::string& feature) override;

    // Extended methods integrating LicenseValidator and FeatureGate
    [[nodiscard]] ValidationResult validateKey(const std::string& key) const;
    [[nodiscard]] std::vector<FeatureDefinition> getEntitlements() const;
    [[nodiscard]] int getSeatCount() const;
    [[nodiscard]] int getRemainingDays() const;
    [[nodiscard]] bool isInGracePeriod() const;

    // Access to sub-components
    [[nodiscard]] FeatureGate& getFeatureGate();
    [[nodiscard]] const FeatureGate& getFeatureGate() const;
    [[nodiscard]] const LicenseValidator& getValidator() const;

private:
    ThreatOne::Core::ModuleLogger logger_;
    LicenseValidator validator_;
    FeatureGate featureGate_;
    LicenseInfo currentLicense_;
    bool activated_ = false;
    bool inGracePeriod_ = false;
    int remainingDays_ = 0;
};

} // namespace ThreatOne::Licensing
