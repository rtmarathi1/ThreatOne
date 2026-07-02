#include "cloud/CloudManager.h"

#include <algorithm>
#include <nlohmann/json.hpp>
#include <mutex>
#include <string>
#include <vector>

namespace ThreatOne::Cloud {

CloudManager::CloudManager()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("CloudManager")) {
    logger_.info("CloudManager initialized");
}

bool CloudManager::sync() {
    std::lock_guard<std::mutex> lock(mutex_);

    syncStatus_ = SyncStatus::Syncing;
    totalItemsSynced_ += 10; // Simulate syncing items
    lastSyncTime_ = "now";
    syncStatus_ = SyncStatus::Idle;

    logger_.info("Sync completed: {} total items synced", totalItemsSynced_);
    return true;
}

SyncResult CloudManager::syncWithConflictResolution(ConflictResolution resolution) {
    std::lock_guard<std::mutex> lock(mutex_);

    syncStatus_ = SyncStatus::Syncing;

    SyncResult result;
    result.timestamp = "now";

    switch (resolution) {
        case ConflictResolution::LocalWins:
            result.success = true;
            result.itemsSynced = 10;
            totalItemsSynced_ += result.itemsSynced;
            logger_.info("Sync with LocalWins resolution: {} items", result.itemsSynced);
            break;

        case ConflictResolution::RemoteWins:
            result.success = true;
            result.itemsSynced = 10;
            totalItemsSynced_ += result.itemsSynced;
            logger_.info("Sync with RemoteWins resolution: {} items", result.itemsSynced);
            break;

        case ConflictResolution::Manual:
            result.success = false;
            result.itemsSynced = 5;
            result.conflicts.push_back("config_policy_v2");
            result.conflicts.push_back("endpoint_settings_v3");
            totalItemsSynced_ += result.itemsSynced;
            syncStatus_ = SyncStatus::Conflict;
            logger_.info("Sync with Manual resolution: {} conflicts detected", result.conflicts.size());
            return result;
    }

    lastSyncTime_ = result.timestamp;
    syncStatus_ = SyncStatus::Idle;
    return result;
}

SyncStatus CloudManager::getSyncStatus() {
    std::lock_guard<std::mutex> lock(mutex_);
    return syncStatus_;
}

CloudStatus CloudManager::getStatus() {
    std::lock_guard<std::mutex> lock(mutex_);

    CloudStatus status;
    status.connected = true;
    status.lastSync = lastSyncTime_;
    status.accountId = "cloud-account-001";
    status.storageUsed = 0;
    for (const auto& [id, backup] : backups_) {
        status.storageUsed += backup.size;
    }
    status.storageTotal = 1073741824; // 1 GB

    return status;
}

bool CloudManager::backup(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = "BKP-" + std::to_string(nextBackupId_++);
    BackupInfo info;
    info.id = id;
    info.name = name;
    info.timestamp = "now";
    info.size = 1024;
    info.encrypted = false;
    backups_[id] = info;

    logger_.info("Created backup: id={}, name={}", id, name);
    return true;
}

bool CloudManager::restore(const std::string& backupId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = backups_.find(backupId);
    if (it == backups_.end()) {
        logger_.warn("restore failed: backup {} not found", backupId);
        return false;
    }

    logger_.info("Restored backup: id={}, name={}", backupId, it->second.name);
    return true;
}

std::vector<BackupInfo> CloudManager::listBackups() {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<BackupInfo> result;
    result.reserve(backups_.size());
    for (const auto& [id, backup] : backups_) {
        result.push_back(backup);
    }
    return result;
}

bool CloudManager::deleteBackup(const std::string& backupId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = backups_.find(backupId);
    if (it == backups_.end()) {
        logger_.warn("deleteBackup failed: backup {} not found", backupId);
        return false;
    }

    logger_.info("Deleted backup: id={}, name={}", backupId, it->second.name);
    backups_.erase(it);
    return true;
}

std::string CloudManager::distributePolicy(const PolicyInfo& policy) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = "POL-" + std::to_string(nextPolicyId_++);
    PolicyInfo stored = policy;
    stored.id = id;
    stored.distributedAt = "now";
    policies_[id] = stored;

    logger_.info("Distributed policy: id={}, name={}, version={}", id, policy.name, policy.version);
    return id;
}

std::vector<PolicyInfo> CloudManager::getPolicies() {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<PolicyInfo> result;
    result.reserve(policies_.size());
    for (const auto& [id, policy] : policies_) {
        result.push_back(policy);
    }
    return result;
}

bool CloudManager::acknowledgePolicy(const std::string& policyId, const std::string& endpointId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = policies_.find(policyId);
    if (it == policies_.end()) {
        logger_.warn("acknowledgePolicy failed: policy {} not found", policyId);
        return false;
    }

    // Check if already acknowledged
    auto& ackList = it->second.acknowledgedBy;
    if (std::find(ackList.begin(), ackList.end(), endpointId) != ackList.end()) {
        logger_.info("Policy {} already acknowledged by {}", policyId, endpointId);
        return true;
    }

    ackList.push_back(endpointId);
    logger_.info("Policy {} acknowledged by endpoint {}", policyId, endpointId);
    return true;
}

std::string CloudManager::createBackupSchedule(const BackupSchedule& schedule) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = "SCHED-" + std::to_string(nextScheduleId_++);
    BackupSchedule stored = schedule;
    stored.id = id;
    backupSchedules_[id] = stored;

    logger_.info("Created backup schedule: id={}, name={}, frequency={}", id, schedule.name, schedule.frequency);
    return id;
}

std::vector<BackupSchedule> CloudManager::getBackupSchedules() {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<BackupSchedule> result;
    result.reserve(backupSchedules_.size());
    for (const auto& [id, sched] : backupSchedules_) {
        result.push_back(sched);
    }
    return result;
}

bool CloudManager::uploadThreatIntel(const std::string& data) {
    std::lock_guard<std::mutex> lock(mutex_);
    logger_.info("uploadThreatIntel: {} bytes", data.size());
    return true;
}

std::string CloudManager::downloadPolicies() {
    std::lock_guard<std::mutex> lock(mutex_);

    // Use nlohmann_json for proper JSON construction with escaping
    nlohmann::json j;
    j["policies"] = nlohmann::json::array();
    for (const auto& [id, policy] : policies_) {
        nlohmann::json policyObj;
        policyObj["id"] = id;
        policyObj["name"] = policy.name;
        j["policies"].push_back(policyObj);
    }

    logger_.info("downloadPolicies: {} policies", policies_.size());
    return j.dump();
}

} // namespace ThreatOne::Cloud
