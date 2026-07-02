#include "updates/RollbackManager.h"

#include <algorithm>
#include <chrono>
#include <sstream>

namespace ThreatOne::Updates {

RollbackManager::RollbackManager()
    : logger_(Core::Logger::instance().getModuleLogger("RollbackManager")) {
    logger_.info("RollbackManager initialized");
}

std::string RollbackManager::generateBackupId() {
    return "BKP-" + std::to_string(nextBackupId_++);
}

std::string RollbackManager::generateOperationId() {
    return "RBOP-" + std::to_string(nextOpId_++);
}

std::string RollbackManager::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << time;
    return oss.str();
}

std::string RollbackManager::createBackupPoint(const std::string& version,
                                                const std::string& description) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = generateBackupId();
    BackupPoint bp;
    bp.id = id;
    bp.version = version;
    bp.createdAt = getCurrentTimestamp();
    bp.sizeBytes = 1024 * 1024;  // Simulated 1MB
    bp.description = description.empty() ? "Backup of version " + version : description;
    bp.valid = true;

    backups_.push_back(bp);
    logger_.info("Created backup point: {} (version {})", id, version);
    return id;
}

bool RollbackManager::deleteBackupPoint(const std::string& backupId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = std::find_if(backups_.begin(), backups_.end(),
                           [&backupId](const BackupPoint& bp) { return bp.id == backupId; });
    if (it == backups_.end()) return false;
    backups_.erase(it);
    return true;
}

std::vector<BackupPoint> RollbackManager::getBackupPoints() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return backups_;
}

std::optional<BackupPoint> RollbackManager::getBackupPoint(const std::string& backupId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& bp : backups_) {
        if (bp.id == backupId) return bp;
    }
    return std::nullopt;
}

std::optional<BackupPoint> RollbackManager::getLatestBackup() const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (backups_.empty()) return std::nullopt;
    return backups_.back();
}

bool RollbackManager::rollback(const std::string& fromVersion, const std::string& toVersion) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (toVersion.empty()) return false;

    RollbackOperation op;
    op.id = generateOperationId();
    op.fromVersion = fromVersion;
    op.toVersion = toVersion;
    op.performedAt = getCurrentTimestamp();
    op.success = true;

    currentVersion_ = toVersion;
    history_.push_back(op);
    logger_.info("Rolled back: {} -> {}", fromVersion, toVersion);
    return true;
}

bool RollbackManager::rollbackToBackup(const std::string& backupId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = std::find_if(backups_.begin(), backups_.end(),
                           [&backupId](const BackupPoint& bp) { return bp.id == backupId; });
    if (it == backups_.end() || !it->valid) return false;

    std::string fromVersion = currentVersion_;
    currentVersion_ = it->version;

    RollbackOperation op;
    op.id = generateOperationId();
    op.fromVersion = fromVersion;
    op.toVersion = it->version;
    op.performedAt = getCurrentTimestamp();
    op.success = true;

    history_.push_back(op);
    logger_.info("Rolled back to backup {}: {} -> {}", backupId, fromVersion, it->version);
    return true;
}

bool RollbackManager::canRollback() const {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& bp : backups_) {
        if (bp.valid && bp.version != currentVersion_) {
            return true;
        }
    }
    return false;
}

std::string RollbackManager::getCurrentVersion() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return currentVersion_;
}

void RollbackManager::setCurrentVersion(const std::string& version) {
    std::lock_guard<std::mutex> lock(mutex_);
    currentVersion_ = version;
}

std::vector<RollbackOperation> RollbackManager::getRollbackHistory() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return history_;
}

uint64_t RollbackManager::getRollbackCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return history_.size();
}

void RollbackManager::pruneOldBackups(uint64_t maxBackups) {
    std::lock_guard<std::mutex> lock(mutex_);

    while (backups_.size() > maxBackups) {
        backups_.erase(backups_.begin());
    }
}

void RollbackManager::invalidateBackup(const std::string& backupId) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& bp : backups_) {
        if (bp.id == backupId) {
            bp.valid = false;
            break;
        }
    }
}

uint64_t RollbackManager::getTotalBackupSize() const {
    std::lock_guard<std::mutex> lock(mutex_);

    uint64_t total = 0;
    for (const auto& bp : backups_) {
        total += bp.sizeBytes;
    }
    return total;
}

} // namespace ThreatOne::Updates
