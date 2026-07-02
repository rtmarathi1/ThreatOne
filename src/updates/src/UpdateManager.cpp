#include "updates/UpdateManager.h"

#include <algorithm>
#include <memory>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace ThreatOne::Updates {

UpdateManager::UpdateManager()
    : versionChecker_(std::make_shared<VersionChecker>()),
      deltaUpdater_(std::make_shared<DeltaUpdater>()),
      rollbackManager_(std::make_shared<RollbackManager>()),
      updateVerifier_(std::make_shared<UpdateVerifier>()),
      channelManager_(std::make_shared<ChannelManager>()),
      updateScheduler_(std::make_shared<UpdateScheduler>()),
      logger_("UpdateManager") {
    logger_.info("Update Manager initialized");
}

std::string UpdateManager::generateId() {
    std::ostringstream oss;
    oss << "UPD-" << nextId_;
    ++nextId_;
    return oss.str();
}

std::string UpdateManager::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf{};
#ifdef _WIN32
    gmtime_s(&tm_buf, &time_t_now);
#else
    gmtime_r(&time_t_now, &tm_buf);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

std::vector<UpdateInfo> UpdateManager::checkForUpdates() {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<UpdateInfo> filtered;
    for (const auto& update : availableUpdates_) {
        // Return updates matching current channel or lower stability
        switch (channel_) {
            case UpdateChannel::Nightly:
                // Nightly gets all updates
                filtered.push_back(update);
                break;
            case UpdateChannel::Beta:
                // Beta gets stable and beta updates
                if (update.channel == UpdateChannel::Stable ||
                    update.channel == UpdateChannel::Beta) {
                    filtered.push_back(update);
                }
                break;
            case UpdateChannel::Stable:
                // Stable only gets stable updates
                if (update.channel == UpdateChannel::Stable) {
                    filtered.push_back(update);
                }
                break;
        }
    }

    logger_.info("Found {} updates for channel", filtered.size());
    return filtered;
}

bool UpdateManager::downloadUpdate(const std::string& version) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Find the update
    bool found = false;
    uint64_t totalSize = 0;
    for (const auto& update : availableUpdates_) {
        if (update.version == version) {
            found = true;
            totalSize = update.size;
            break;
        }
    }

    if (!found) {
        logger_.error("Update version {} not found", version);
        return false;
    }

    // Check if already downloading or downloaded
    auto progressIt = progress_.find(version);
    if (progressIt != progress_.end()) {
        if (progressIt->second.status == UpdateStatus::Downloaded ||
            progressIt->second.status == UpdateStatus::Installed) {
            logger_.warn("Update {} already processed", version);
            return false;
        }
    }

    // Simulate download (set status to Downloaded immediately)
    UpdateProgress prog;
    prog.version = version;
    prog.status = UpdateStatus::Downloaded;
    prog.totalBytes = totalSize;
    prog.bytesDownloaded = totalSize;
    prog.percentage = 100.0;
    progress_[version] = prog;

    logger_.info("Downloaded update version {}", version);
    return true;
}

bool UpdateManager::installUpdate(const std::string& version) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto progressIt = progress_.find(version);
    if (progressIt == progress_.end()) {
        logger_.error("Update {} has not been downloaded", version);
        return false;
    }

    if (progressIt->second.status != UpdateStatus::Downloaded) {
        logger_.error("Update {} is not ready for installation (status: {})",
                      version, static_cast<int>(progressIt->second.status));
        return false;
    }

    // Check version compatibility
    auto compatIt = compatibilityMatrix_.find(version);
    if (compatIt != compatibilityMatrix_.end() && !compatIt->second.compatible) {
        logger_.error("Update {} is not compatible with current version", version);
        progressIt->second.status = UpdateStatus::Failed;

        UpdateHistoryEntry entry;
        entry.version = version;
        entry.status = UpdateStatus::Failed;
        entry.timestamp = getCurrentTimestamp();
        entry.description = "Installation failed: incompatible version";
        history_.push_back(entry);
        return false;
    }

    // Install
    progressIt->second.status = UpdateStatus::Installed;
    previousVersion_ = currentVersion_;
    currentVersion_ = version;

    UpdateHistoryEntry entry;
    entry.version = version;
    entry.status = UpdateStatus::Installed;
    entry.timestamp = getCurrentTimestamp();
    entry.description = "Update installed successfully";
    history_.push_back(entry);

    logger_.info("Installed update version {} (previous: {})", version, previousVersion_);
    return true;
}

VersionInfo UpdateManager::getVersion() {
    std::lock_guard<std::mutex> lock(mutex_);

    VersionInfo info;
    info.current = currentVersion_;

    // Find latest available version
    std::string latest = currentVersion_;
    for (const auto& update : availableUpdates_) {
        if (update.version > latest) {
            latest = update.version;
        }
    }
    info.latest = latest;
    info.updateAvailable = (latest != currentVersion_);

    return info;
}

bool UpdateManager::rollback() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (previousVersion_.empty()) {
        logger_.error("No previous version to roll back to");
        return false;
    }

    std::string rolledBackFrom = currentVersion_;
    currentVersion_ = previousVersion_;
    previousVersion_.clear();

    // Update progress for the version we rolled back from
    auto progressIt = progress_.find(rolledBackFrom);
    if (progressIt != progress_.end()) {
        progressIt->second.status = UpdateStatus::RolledBack;
    }

    UpdateHistoryEntry entry;
    entry.version = rolledBackFrom;
    entry.status = UpdateStatus::RolledBack;
    entry.timestamp = getCurrentTimestamp();
    entry.description = "Rolled back to version " + currentVersion_;
    history_.push_back(entry);

    logger_.info("Rolled back from {} to {}", rolledBackFrom, currentVersion_);
    return true;
}

bool UpdateManager::cancelUpdate(const std::string& version) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto progressIt = progress_.find(version);
    if (progressIt == progress_.end()) {
        logger_.error("No update in progress for version {}", version);
        return false;
    }

    if (progressIt->second.status == UpdateStatus::Installed ||
        progressIt->second.status == UpdateStatus::RolledBack) {
        logger_.error("Cannot cancel update {}: already completed", version);
        return false;
    }

    progress_.erase(progressIt);
    logger_.info("Cancelled update for version {}", version);
    return true;
}

void UpdateManager::setUpdateChannel(UpdateChannel channel) {
    std::lock_guard<std::mutex> lock(mutex_);
    channel_ = channel;
    logger_.info("Update channel set to {}", static_cast<int>(channel));
}

UpdateChannel UpdateManager::getUpdateChannel() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return channel_;
}

std::optional<UpdateProgress> UpdateManager::getUpdateProgress(const std::string& version) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = progress_.find(version);
    if (it == progress_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::optional<StagedRollout> UpdateManager::stageRollout(const std::string& version, int percentage) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (percentage < 0 || percentage > 100) {
        logger_.error("Invalid rollout percentage: {}", percentage);
        return std::nullopt;
    }

    // Check if rollout already exists for this version
    auto it = rollouts_.find(version);
    if (it != rollouts_.end()) {
        // Update existing rollout percentage
        it->second.percentage = percentage;
        it->second.status = (percentage == 100) ? UpdateStatus::Installed : UpdateStatus::Installing;
        logger_.info("Updated staged rollout for {} to {}%", version, percentage);
        return it->second;
    }

    StagedRollout rollout;
    rollout.id = generateId();
    rollout.version = version;
    rollout.percentage = percentage;
    rollout.startedAt = getCurrentTimestamp();
    rollout.status = (percentage == 100) ? UpdateStatus::Installed : UpdateStatus::Installing;

    rollouts_[version] = rollout;
    logger_.info("Created staged rollout for {} at {}%", version, percentage);
    return rollout;
}

std::vector<SignatureUpdate> UpdateManager::getSignatureUpdates() {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<SignatureUpdate> result;
    result.reserve(signatureUpdates_.size());
    for (const auto& [id, update] : signatureUpdates_) {
        result.push_back(update);
    }
    return result;
}

bool UpdateManager::downloadSignatureUpdate(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = signatureUpdates_.find(id);
    if (it == signatureUpdates_.end()) {
        logger_.error("Signature update {} not found", id);
        return false;
    }

    // Mark as downloaded (simulate)
    signatureInstalled_[id] = false;  // downloaded but not installed
    logger_.info("Downloaded signature update: {} (type: {})", id, it->second.type);
    return true;
}

bool UpdateManager::installSignatureUpdate(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = signatureUpdates_.find(id);
    if (it == signatureUpdates_.end()) {
        logger_.error("Signature update {} not found", id);
        return false;
    }

    auto downloadIt = signatureInstalled_.find(id);
    if (downloadIt == signatureInstalled_.end()) {
        logger_.error("Signature update {} has not been downloaded", id);
        return false;
    }

    if (downloadIt->second) {
        logger_.warn("Signature update {} already installed", id);
        return false;
    }

    signatureInstalled_[id] = true;

    UpdateHistoryEntry entry;
    entry.version = it->second.version;
    entry.status = UpdateStatus::Installed;
    entry.timestamp = getCurrentTimestamp();
    entry.description = "Signature update installed: " + it->second.type + " " + it->second.version;
    history_.push_back(entry);

    logger_.info("Installed signature update: {} ({})", id, it->second.type);
    return true;
}

VersionCompatibility UpdateManager::checkVersionCompatibility(const std::string& version) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = compatibilityMatrix_.find(version);
    if (it != compatibilityMatrix_.end()) {
        return it->second;
    }

    // Default: compatible if no explicit incompatibility registered
    VersionCompatibility compat;
    compat.minVersion = "1.0.0";
    compat.maxVersion = version;
    compat.compatible = true;
    compat.notes = "No compatibility restrictions";
    return compat;
}

std::vector<UpdateHistoryEntry> UpdateManager::getUpdateHistory() {
    std::lock_guard<std::mutex> lock(mutex_);
    return history_;
}

void UpdateManager::addAvailableUpdate(const UpdateInfo& update) {
    std::lock_guard<std::mutex> lock(mutex_);
    availableUpdates_.push_back(update);
    logger_.info("Added available update: {} (channel: {})",
                 update.version, static_cast<int>(update.channel));
}

void UpdateManager::addSignatureUpdate(const SignatureUpdate& update) {
    std::lock_guard<std::mutex> lock(mutex_);
    signatureUpdates_[update.id] = update;
    logger_.info("Added signature update: {} (type: {})", update.id, update.type);
}

void UpdateManager::setCurrentVersion(const std::string& version) {
    std::lock_guard<std::mutex> lock(mutex_);
    currentVersion_ = version;
}

void UpdateManager::setCompatibilityMatrix(const std::string& version,
                                            const VersionCompatibility& compat) {
    std::lock_guard<std::mutex> lock(mutex_);
    compatibilityMatrix_[version] = compat;
}

} // namespace ThreatOne::Updates
