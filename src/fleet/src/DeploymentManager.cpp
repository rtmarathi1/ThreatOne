#include "fleet/DeploymentManager.h"

#include <algorithm>
#include <sstream>
#include <cmath>

namespace ThreatOne::Fleet {

DeploymentManager::DeploymentManager()
    : logger_("DeploymentManager") {
    logger_.info("Deployment Manager initialized");
}

std::string DeploymentManager::generateId() const {
    std::ostringstream oss;
    oss << "dep-" << nextId_;
    return oss.str();
}

void DeploymentManager::buildStages(DeploymentInfo& deployment) {
    deployment.stages.clear();
    int totalEndpoints = static_cast<int>(deployment.targetEndpoints.size());
    int stageCount = deployment.config.stages;
    if (stageCount <= 0) stageCount = 1;

    int perStage = std::max(1, totalEndpoints / stageCount);
    int idx = 0;

    for (int s = 0; s < stageCount && idx < totalEndpoints; ++s) {
        RolloutStage stage;
        stage.stageNumber = s + 1;
        int end = (s == stageCount - 1) ? totalEndpoints : std::min(idx + perStage, totalEndpoints);
        for (int i = idx; i < end; ++i) {
            stage.endpointIds.push_back(deployment.targetEndpoints[i]);
        }
        idx = end;
        deployment.stages.push_back(stage);
    }
}

std::string DeploymentManager::createDeployment(const std::string& version,
                                                  const std::vector<std::string>& targetEndpoints,
                                                  const RolloutConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);

    DeploymentInfo dep;
    dep.id = generateId();
    ++nextId_;
    dep.version = version;
    dep.targetEndpoints = targetEndpoints;
    dep.config = config;
    dep.status = DeploymentStatus::Planned;
    dep.currentStage = 0;

    // Determine previous version from first endpoint
    if (!targetEndpoints.empty()) {
        auto it = endpointVersions_.find(targetEndpoints[0]);
        if (it != endpointVersions_.end()) {
            dep.previousVersion = it->second.version;
            dep.rollbackVersion = it->second.version;
        }
    }

    buildStages(dep);

    deployments_[dep.id] = dep;
    logger_.info("Created deployment {} for version {} ({} endpoints)",
                 dep.id, version, targetEndpoints.size());
    return dep.id;
}

bool DeploymentManager::startRollout(const std::string& deploymentId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = deployments_.find(deploymentId);
    if (it == deployments_.end()) return false;

    if (it->second.status != DeploymentStatus::Planned) return false;

    it->second.status = DeploymentStatus::InProgress;
    it->second.startedAt = std::chrono::system_clock::now();
    it->second.currentStage = 1;
    logger_.info("Started rollout: {}", deploymentId);
    return true;
}

bool DeploymentManager::pauseRollout(const std::string& deploymentId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = deployments_.find(deploymentId);
    if (it == deployments_.end()) return false;

    if (it->second.status != DeploymentStatus::InProgress) return false;

    it->second.status = DeploymentStatus::Paused;
    logger_.info("Paused rollout: {}", deploymentId);
    return true;
}

bool DeploymentManager::resumeRollout(const std::string& deploymentId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = deployments_.find(deploymentId);
    if (it == deployments_.end()) return false;

    if (it->second.status != DeploymentStatus::Paused) return false;

    it->second.status = DeploymentStatus::InProgress;
    logger_.info("Resumed rollout: {}", deploymentId);
    return true;
}

bool DeploymentManager::rollback(const std::string& deploymentId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = deployments_.find(deploymentId);
    if (it == deployments_.end()) return false;

    if (it->second.status == DeploymentStatus::RolledBack ||
        it->second.status == DeploymentStatus::Planned) {
        return false;
    }

    // Restore endpoints to previous version
    if (!it->second.rollbackVersion.empty()) {
        for (const auto& epId : it->second.targetEndpoints) {
            auto epIt = endpointVersions_.find(epId);
            if (epIt != endpointVersions_.end()) {
                epIt->second.version = it->second.rollbackVersion;
                epIt->second.updatedAt = std::chrono::system_clock::now();
            }
        }
    }

    it->second.status = DeploymentStatus::RolledBack;
    it->second.completedAt = std::chrono::system_clock::now();
    logger_.info("Rolled back deployment: {}", deploymentId);
    return true;
}

std::optional<DeploymentInfo> DeploymentManager::getDeploymentStatus(const std::string& deploymentId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = deployments_.find(deploymentId);
    if (it == deployments_.end()) return std::nullopt;
    return it->second;
}

std::vector<DeploymentInfo> DeploymentManager::getDeployments() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<DeploymentInfo> result;
    result.reserve(deployments_.size());
    for (const auto& [id, dep] : deployments_) {
        result.push_back(dep);
    }
    return result;
}

std::vector<VersionDistribution> DeploymentManager::getVersionDistribution() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::unordered_map<std::string, int> versionCounts;
    for (const auto& [epId, epVer] : endpointVersions_) {
        versionCounts[epVer.version]++;
    }

    int total = static_cast<int>(endpointVersions_.size());
    std::vector<VersionDistribution> result;
    for (const auto& [ver, count] : versionCounts) {
        VersionDistribution vd;
        vd.version = ver;
        vd.count = count;
        vd.percentage = total > 0 ? (static_cast<double>(count) / total) * 100.0 : 0.0;
        result.push_back(vd);
    }

    // Sort by count descending
    std::sort(result.begin(), result.end(),
              [](const VersionDistribution& a, const VersionDistribution& b) {
                  return a.count > b.count;
              });

    return result;
}

bool DeploymentManager::advanceStage(const std::string& deploymentId, int successes, int failures) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = deployments_.find(deploymentId);
    if (it == deployments_.end()) return false;

    if (it->second.status != DeploymentStatus::InProgress) return false;

    int stageIdx = it->second.currentStage - 1;
    if (stageIdx < 0 || stageIdx >= static_cast<int>(it->second.stages.size())) {
        return false;
    }

    auto& stage = it->second.stages[stageIdx];
    stage.successCount = successes;
    stage.failureCount = failures;
    stage.completed = true;

    // Update endpoint versions for successful ones
    int updated = 0;
    for (const auto& epId : stage.endpointIds) {
        if (updated < successes) {
            endpointVersions_[epId] = {epId, it->second.version, std::chrono::system_clock::now()};
            updated++;
        }
    }

    // Check auto-rollback threshold
    int totalInStage = successes + failures;
    if (totalInStage > 0) {
        double failurePercent = (static_cast<double>(failures) / totalInStage) * 100.0;
        if (failurePercent >= it->second.config.autoRollbackOnFailurePercent) {
            it->second.status = DeploymentStatus::Failed;
            logger_.warn("Deployment {} failed: {}% failure rate in stage {}",
                         deploymentId, failurePercent, it->second.currentStage);
            return true;
        }
    }

    // Move to next stage or complete
    if (it->second.currentStage >= static_cast<int>(it->second.stages.size())) {
        it->second.status = DeploymentStatus::Completed;
        it->second.completedAt = std::chrono::system_clock::now();
        logger_.info("Deployment {} completed", deploymentId);
    } else {
        it->second.currentStage++;
    }

    return true;
}

void DeploymentManager::setEndpointVersion(const std::string& endpointId, const std::string& version) {
    std::lock_guard<std::mutex> lock(mutex_);
    endpointVersions_[endpointId] = {endpointId, version, std::chrono::system_clock::now()};
}

std::optional<std::string> DeploymentManager::getEndpointVersion(const std::string& endpointId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = endpointVersions_.find(endpointId);
    if (it == endpointVersions_.end()) return std::nullopt;
    return it->second.version;
}

} // namespace ThreatOne::Fleet
