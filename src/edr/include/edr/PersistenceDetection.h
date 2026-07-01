#pragma once

#include <string>
#include <vector>
#include <mutex>

#include "edr/IEDREngine.h"
#include "core/Logger.h"

namespace ThreatOne::EDR {

class PersistenceDetection {
public:
    PersistenceDetection();
    ~PersistenceDetection() = default;

    // Scan for all known persistence mechanisms
    [[nodiscard]] std::vector<PersistenceIndicator> scanForPersistence() const;

    // Individual checks
    [[nodiscard]] std::vector<PersistenceIndicator> checkCronJobs() const;
    [[nodiscard]] std::vector<PersistenceIndicator> checkSystemdUnits() const;
    [[nodiscard]] std::vector<PersistenceIndicator> checkInitScripts() const;
    [[nodiscard]] std::vector<PersistenceIndicator> checkShellProfiles() const;
    [[nodiscard]] std::vector<PersistenceIndicator> checkLdPreload() const;
    [[nodiscard]] std::vector<PersistenceIndicator> checkRcLocal() const;

    // Allow injecting mock paths for testing
    void setBasePath(const std::string& basePath);

private:
    [[nodiscard]] bool pathExists(const std::string& path) const;
    [[nodiscard]] std::string readFileContents(const std::string& path) const;

    mutable std::mutex mutex_;
    Core::ModuleLogger logger_;
    std::string basePath_; // For testing - prefix all path checks with this
};

} // namespace ThreatOne::EDR
