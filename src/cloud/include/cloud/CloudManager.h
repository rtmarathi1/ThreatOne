#pragma once

#include "cloud/ICloudManager.h"
#include "core/Logger.h"

namespace ThreatOne::Cloud {

class CloudManager : public ICloudManager {
public:
    CloudManager();
    ~CloudManager() override = default;

    bool sync() override;
    bool backup(const std::string& name) override;
    bool restore(const std::string& backupId) override;
    CloudStatus getStatus() override;
    bool uploadThreatIntel(const std::string& data) override;
    std::string downloadPolicies() override;

private:
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Cloud
