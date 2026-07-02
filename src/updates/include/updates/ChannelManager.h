#pragma once

#include "updates/IUpdateManager.h"
#include "core/Logger.h"

#include <mutex>
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace ThreatOne::Updates {

struct ChannelConfig {
    UpdateChannel channel = UpdateChannel::Stable;
    std::string name;
    std::string description;
    bool autoUpdate = false;
    int checkIntervalHours = 24;
    int rolloutPercentage = 100;
};

struct RolloutStatus {
    std::string id;
    std::string version;
    UpdateChannel channel = UpdateChannel::Stable;
    int targetPercentage = 0;
    int currentPercentage = 0;
    std::string startedAt;
    std::string completedAt;
    bool active = false;
};

class ChannelManager {
public:
    ChannelManager();
    ~ChannelManager() = default;

    // Channel management
    void setActiveChannel(UpdateChannel channel);
    [[nodiscard]] UpdateChannel getActiveChannel() const;
    void setChannelConfig(UpdateChannel channel, const ChannelConfig& config);
    [[nodiscard]] ChannelConfig getChannelConfig(UpdateChannel channel) const;
    [[nodiscard]] std::vector<ChannelConfig> getAllChannelConfigs() const;

    // Staged rollouts
    std::string startRollout(const std::string& version, UpdateChannel channel, int percentage);
    bool updateRolloutPercentage(const std::string& rolloutId, int percentage);
    bool completeRollout(const std::string& rolloutId);
    bool cancelRollout(const std::string& rolloutId);
    [[nodiscard]] std::vector<RolloutStatus> getActiveRollouts() const;
    [[nodiscard]] std::optional<RolloutStatus> getRollout(const std::string& rolloutId) const;

    // Eligibility
    bool isEligibleForUpdate(const std::string& version, int rolloutPercentage) const;
    bool isChannelAvailable(UpdateChannel channel) const;

    // Statistics
    [[nodiscard]] uint64_t getTotalRollouts() const;
    [[nodiscard]] uint64_t getActiveRolloutCount() const;

private:
    std::string generateRolloutId();
    std::string getCurrentTimestamp() const;
    void initDefaultConfigs();

    mutable std::mutex mutex_;
    UpdateChannel activeChannel_ = UpdateChannel::Stable;
    std::unordered_map<int, ChannelConfig> channelConfigs_; // channel int -> config
    std::unordered_map<std::string, RolloutStatus> rollouts_;
    uint64_t totalRollouts_ = 0;
    int nextRolloutId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Updates
