#include "cloud/CloudManager.h"

#include <nlohmann/json.hpp>
#include <mutex>
#include <string>
#include <vector>

namespace ThreatOne::Cloud {

CloudManager::CloudManager()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("CloudManager")) {
    // Initialize sub-components
    syncService_ = std::make_shared<CloudSyncService>();
    backupManager_ = std::make_shared<CloudBackupManager>();
    policyManager_ = std::make_shared<CloudPolicyManager>();
    deviceManager_ = std::make_shared<DeviceManager>();
    remoteScanService_ = std::make_shared<RemoteScanService>();
    assetDiscovery_ = std::make_shared<CloudAssetDiscovery>();

    logger_.info("CloudManager initialized with all sub-components");
}

bool CloudManager::sync() {
    return syncService_->performSync();
}

SyncResult CloudManager::syncWithConflictResolution(ConflictResolution resolution) {
    return syncService_->performSyncWithResolution(resolution);
}

SyncStatus CloudManager::getSyncStatus() {
    return syncService_->getStatus();
}

CloudStatus CloudManager::getStatus() {
    CloudStatus status;
    status.connected = true;
    status.lastSync = syncService_->getLastSyncTime();
    status.accountId = "cloud-account-001";
    status.storageUsed = backupManager_->getTotalStorageUsed();
    status.storageTotal = 1073741824; // 1 GB

    return status;
}

bool CloudManager::backup(const std::string& name) {
    std::string id = backupManager_->createBackup(name);
    return !id.empty();
}

bool CloudManager::restore(const std::string& backupId) {
    return backupManager_->restoreBackup(backupId);
}

std::vector<BackupInfo> CloudManager::listBackups() {
    return backupManager_->listBackups();
}

bool CloudManager::deleteBackup(const std::string& backupId) {
    return backupManager_->deleteBackup(backupId);
}

std::string CloudManager::distributePolicy(const PolicyInfo& policy) {
    return policyManager_->distributePolicy(policy);
}

std::vector<PolicyInfo> CloudManager::getPolicies() {
    return policyManager_->getPolicies();
}

bool CloudManager::acknowledgePolicy(const std::string& policyId, const std::string& endpointId) {
    return policyManager_->acknowledgePolicy(policyId, endpointId);
}

std::string CloudManager::createBackupSchedule(const BackupSchedule& schedule) {
    return backupManager_->createSchedule(schedule);
}

std::vector<BackupSchedule> CloudManager::getBackupSchedules() {
    return backupManager_->getSchedules();
}

bool CloudManager::uploadThreatIntel(const std::string& data) {
    logger_.info("uploadThreatIntel: {} bytes", data.size());
    return true;
}

std::string CloudManager::downloadPolicies() {
    auto policies = policyManager_->getPolicies();

    nlohmann::json j;
    j["policies"] = nlohmann::json::array();
    for (const auto& policy : policies) {
        nlohmann::json policyObj;
        policyObj["id"] = policy.id;
        policyObj["name"] = policy.name;
        j["policies"].push_back(policyObj);
    }

    logger_.info("downloadPolicies: {} policies", policies.size());
    return j.dump();
}

} // namespace ThreatOne::Cloud
