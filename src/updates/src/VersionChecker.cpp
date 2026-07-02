#include "updates/VersionChecker.h"

#include <algorithm>
#include <chrono>
#include <sstream>

namespace ThreatOne::Updates {

VersionChecker::VersionChecker()
    : logger_(Core::Logger::instance().getModuleLogger("VersionChecker")) {
    logger_.info("VersionChecker initialized");
}

std::string VersionChecker::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << time;
    return oss.str();
}

std::vector<int> VersionChecker::parseVersion(const std::string& version) const {
    std::vector<int> parts;
    std::istringstream iss(version);
    std::string token;
    while (std::getline(iss, token, '.')) {
        // Strip non-numeric suffix (e.g., "1-beta" -> "1")
        std::string numeric;
        for (char c : token) {
            if (c >= '0' && c <= '9') {
                numeric += c;
            } else {
                break;
            }
        }
        if (!numeric.empty()) {
            parts.push_back(std::stoi(numeric));
        }
    }
    return parts;
}

int VersionChecker::compareVersions(const std::string& v1, const std::string& v2) const {
    auto parts1 = parseVersion(v1);
    auto parts2 = parseVersion(v2);

    size_t maxLen = std::max(parts1.size(), parts2.size());
    parts1.resize(maxLen, 0);
    parts2.resize(maxLen, 0);

    for (size_t i = 0; i < maxLen; ++i) {
        if (parts1[i] < parts2[i]) return -1;
        if (parts1[i] > parts2[i]) return 1;
    }
    return 0;
}

bool VersionChecker::isNewerVersion(const std::string& candidate, const std::string& current) const {
    return compareVersions(candidate, current) > 0;
}

bool VersionChecker::isCompatibleVersion(const std::string& version, const std::string& minVersion,
                                          const std::string& maxVersion) const {
    return compareVersions(version, minVersion) >= 0 && compareVersions(version, maxVersion) <= 0;
}

std::vector<UpdateInfo> VersionChecker::checkForUpdates(UpdateChannel channel) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return filterByChannel(availableUpdates_, channel);
}

UpdateCheckResult VersionChecker::performUpdateCheck(UpdateChannel channel) {
    std::lock_guard<std::mutex> lock(mutex_);
    ++totalChecks_;
    lastCheckTime_ = getCurrentTimestamp();

    UpdateCheckResult result;
    result.checkedAt = lastCheckTime_;
    result.channel = channel;
    result.success = true;
    result.availableUpdates = filterByChannel(availableUpdates_, channel);

    lastCheckResult_ = result;
    logger_.info("Update check performed: {} updates found", result.availableUpdates.size());
    return result;
}

std::optional<UpdateCheckResult> VersionChecker::getLastCheckResult() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return lastCheckResult_;
}

void VersionChecker::addAvailableUpdate(const UpdateInfo& update) {
    std::lock_guard<std::mutex> lock(mutex_);
    availableUpdates_.push_back(update);
}

void VersionChecker::removeAvailableUpdate(const std::string& version) {
    std::lock_guard<std::mutex> lock(mutex_);
    availableUpdates_.erase(
        std::remove_if(availableUpdates_.begin(), availableUpdates_.end(),
                       [&version](const UpdateInfo& u) { return u.version == version; }),
        availableUpdates_.end());
}

std::vector<UpdateInfo> VersionChecker::getAvailableUpdates() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return availableUpdates_;
}

std::optional<UpdateInfo> VersionChecker::getUpdate(const std::string& version) const {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& update : availableUpdates_) {
        if (update.version == version) {
            return update;
        }
    }
    return std::nullopt;
}

std::vector<UpdateInfo> VersionChecker::filterByChannel(const std::vector<UpdateInfo>& updates,
                                                         UpdateChannel channel) const {
    std::vector<UpdateInfo> filtered;
    for (const auto& update : updates) {
        switch (channel) {
            case UpdateChannel::Nightly:
                filtered.push_back(update);
                break;
            case UpdateChannel::Beta:
                if (update.channel == UpdateChannel::Stable || update.channel == UpdateChannel::Beta) {
                    filtered.push_back(update);
                }
                break;
            case UpdateChannel::Stable:
                if (update.channel == UpdateChannel::Stable) {
                    filtered.push_back(update);
                }
                break;
        }
    }
    return filtered;
}

std::optional<UpdateInfo> VersionChecker::getLatestForChannel(UpdateChannel channel) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto filtered = filterByChannel(availableUpdates_, channel);
    if (filtered.empty()) return std::nullopt;

    auto it = std::max_element(filtered.begin(), filtered.end(),
        [this](const UpdateInfo& a, const UpdateInfo& b) {
            return compareVersions(a.version, b.version) < 0;
        });
    return *it;
}

uint64_t VersionChecker::getTotalChecks() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return totalChecks_;
}

std::string VersionChecker::getLastCheckTime() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return lastCheckTime_;
}

} // namespace ThreatOne::Updates
