#pragma once

#include "updates/IUpdateManager.h"
#include "core/Logger.h"

#include <mutex>
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace ThreatOne::Updates {

struct VersionComparison {
    std::string version1;
    std::string version2;
    int result = 0;  // -1 = v1 < v2, 0 = equal, 1 = v1 > v2
};

struct UpdateCheckResult {
    std::string checkedAt;
    UpdateChannel channel = UpdateChannel::Stable;
    std::vector<UpdateInfo> availableUpdates;
    bool success = true;
    std::string errorMessage;
};

class VersionChecker {
public:
    VersionChecker();
    ~VersionChecker() = default;

    // Version comparison
    int compareVersions(const std::string& v1, const std::string& v2) const;
    bool isNewerVersion(const std::string& candidate, const std::string& current) const;
    bool isCompatibleVersion(const std::string& version, const std::string& minVersion,
                             const std::string& maxVersion) const;

    // Update checking
    std::vector<UpdateInfo> checkForUpdates(UpdateChannel channel) const;
    UpdateCheckResult performUpdateCheck(UpdateChannel channel);
    [[nodiscard]] std::optional<UpdateCheckResult> getLastCheckResult() const;

    // Available updates management
    void addAvailableUpdate(const UpdateInfo& update);
    void removeAvailableUpdate(const std::string& version);
    [[nodiscard]] std::vector<UpdateInfo> getAvailableUpdates() const;
    [[nodiscard]] std::optional<UpdateInfo> getUpdate(const std::string& version) const;

    // Channel filtering
    std::vector<UpdateInfo> filterByChannel(const std::vector<UpdateInfo>& updates,
                                            UpdateChannel channel) const;
    [[nodiscard]] std::optional<UpdateInfo> getLatestForChannel(UpdateChannel channel) const;

    // Statistics
    [[nodiscard]] uint64_t getTotalChecks() const;
    [[nodiscard]] std::string getLastCheckTime() const;

private:
    std::string getCurrentTimestamp() const;
    std::vector<int> parseVersion(const std::string& version) const;

    mutable std::mutex mutex_;
    std::vector<UpdateInfo> availableUpdates_;
    std::optional<UpdateCheckResult> lastCheckResult_;
    uint64_t totalChecks_ = 0;
    std::string lastCheckTime_;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Updates
