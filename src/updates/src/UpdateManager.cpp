#include "updates/UpdateManager.h"

namespace ThreatOne::Updates {

UpdateManager::UpdateManager()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("UpdateManager")) {
    logger_.info("UpdateManager initialized (stub)");
}

std::vector<UpdateInfo> UpdateManager::checkForUpdates() {
    logger_.info("checkForUpdates called");
    return {};
}

bool UpdateManager::downloadUpdate(const std::string& version) {
    logger_.info("downloadUpdate called: {}", version);
    return true;
}

bool UpdateManager::installUpdate(const std::string& version) {
    logger_.info("installUpdate called: {}", version);
    return true;
}

VersionInfo UpdateManager::getVersion() {
    logger_.info("getVersion called");
    return {"1.0.0", "1.0.0", false};
}

bool UpdateManager::rollback() {
    logger_.info("rollback called");
    return true;
}

} // namespace ThreatOne::Updates
