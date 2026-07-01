#pragma once

#include "updates/IUpdateManager.h"
#include "core/Logger.h"

namespace ThreatOne::Updates {

class UpdateManager : public IUpdateManager {
public:
    UpdateManager();
    ~UpdateManager() override = default;

    std::vector<UpdateInfo> checkForUpdates() override;
    bool downloadUpdate(const std::string& version) override;
    bool installUpdate(const std::string& version) override;
    VersionInfo getVersion() override;
    bool rollback() override;

private:
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Updates
