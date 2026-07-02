#include "updates/ChannelManager.h"

#include <algorithm>
#include <chrono>
#include <sstream>

namespace ThreatOne::Updates {

ChannelManager::ChannelManager()
    : logger_(Core::Logger::instance().getModuleLogger("ChannelManager")) {
    initDefaultConfigs();
    logger_.info("ChannelManager initialized");
}

std::string ChannelManager::generateRolloutId() {
    return "ROLL-" + std::to_string(nextRolloutId_++);
}

std::string ChannelManager::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << time;
    return oss.str();
}

void ChannelManager::initDefaultConfigs() {
    ChannelConfig stable;
    stable.channel = UpdateChannel::Stable;
    stable.name = "Stable";
    stable.description = "Production-ready releases";
    stable.autoUpdate = false;
    stable.checkIntervalHours = 24;
    stable.rolloutPercentage = 100;
    channelConfigs_[static_cast<int>(UpdateChannel::Stable)] = stable;

    ChannelConfig beta;
    beta.channel = UpdateChannel::Beta;
    beta.name = "Beta";
    beta.description = "Pre-release testing builds";
    beta.autoUpdate = false;
    beta.checkIntervalHours = 12;
    beta.rolloutPercentage = 100;
    channelConfigs_[static_cast<int>(UpdateChannel::Beta)] = beta;

    ChannelConfig nightly;
    nightly.channel = UpdateChannel::Nightly;
    nightly.name = "Nightly";
    nightly.description = "Daily development builds";
    nightly.autoUpdate = true;
    nightly.checkIntervalHours = 6;
    nightly.rolloutPercentage = 100;
    channelConfigs_[static_cast<int>(UpdateChannel::Nightly)] = nightly;
}

void ChannelManager::setActiveChannel(UpdateChannel channel) {
    std::lock_guard<std::mutex> lock(mutex_);
    activeChannel_ = channel;
    logger_.info("Active channel set to: {}", static_cast<int>(channel));
}

UpdateChannel ChannelManager::getActiveChannel() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return activeChannel_;
}

void ChannelManager::setChannelConfig(UpdateChannel channel, const ChannelConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    channelConfigs_[static_cast<int>(channel)] = config;
}

ChannelConfig ChannelManager::getChannelConfig(UpdateChannel channel) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = channelConfigs_.find(static_cast<int>(channel));
    if (it == channelConfigs_.end()) {
        return {};
    }
    return it->second;
}

std::vector<ChannelConfig> ChannelManager::getAllChannelConfigs() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ChannelConfig> result;
    for (const auto& [key, config] : channelConfigs_) {
        result.push_back(config);
    }
    return result;
}

std::string ChannelManager::startRollout(const std::string& version, UpdateChannel channel,
                                          int percentage) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (percentage < 0 || percentage > 100) return "";

    std::string id = generateRolloutId();
    RolloutStatus rollout;
    rollout.id = id;
    rollout.version = version;
    rollout.channel = channel;
    rollout.targetPercentage = percentage;
    rollout.currentPercentage = 0;
    rollout.startedAt = getCurrentTimestamp();
    rollout.active = true;

    rollouts_[id] = rollout;
    ++totalRollouts_;
    logger_.info("Started rollout: {} (version {}, {}%)", id, version, percentage);
    return id;
}

bool ChannelManager::updateRolloutPercentage(const std::string& rolloutId, int percentage) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = rollouts_.find(rolloutId);
    if (it == rollouts_.end() || !it->second.active) return false;
    if (percentage < 0 || percentage > 100) return false;

    it->second.currentPercentage = percentage;
    if (percentage >= it->second.targetPercentage) {
        it->second.currentPercentage = it->second.targetPercentage;
    }
    return true;
}

bool ChannelManager::completeRollout(const std::string& rolloutId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = rollouts_.find(rolloutId);
    if (it == rollouts_.end() || !it->second.active) return false;

    it->second.active = false;
    it->second.currentPercentage = it->second.targetPercentage;
    it->second.completedAt = getCurrentTimestamp();
    return true;
}

bool ChannelManager::cancelRollout(const std::string& rolloutId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = rollouts_.find(rolloutId);
    if (it == rollouts_.end() || !it->second.active) return false;

    it->second.active = false;
    it->second.completedAt = getCurrentTimestamp();
    return true;
}

std::vector<RolloutStatus> ChannelManager::getActiveRollouts() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<RolloutStatus> result;
    for (const auto& [id, rollout] : rollouts_) {
        if (rollout.active) result.push_back(rollout);
    }
    return result;
}

std::optional<RolloutStatus> ChannelManager::getRollout(const std::string& rolloutId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = rollouts_.find(rolloutId);
    if (it == rollouts_.end()) return std::nullopt;
    return it->second;
}

bool ChannelManager::isEligibleForUpdate(const std::string& /*version*/, int rolloutPercentage) const {
    // Simple eligibility check: device is eligible if rollout percentage is 100
    return rolloutPercentage >= 100;
}

bool ChannelManager::isChannelAvailable(UpdateChannel channel) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return channelConfigs_.find(static_cast<int>(channel)) != channelConfigs_.end();
}

uint64_t ChannelManager::getTotalRollouts() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return totalRollouts_;
}

uint64_t ChannelManager::getActiveRolloutCount() const {
    std::lock_guard<std::mutex> lock(mutex_);

    uint64_t count = 0;
    for (const auto& [id, rollout] : rollouts_) {
        if (rollout.active) ++count;
    }
    return count;
}

} // namespace ThreatOne::Updates
