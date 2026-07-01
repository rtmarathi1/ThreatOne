#pragma once

// ThreatOne Fleet - Deployment Manager
// Agent deployment tracking, staged rollouts, version management, rollback

#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <optional>
#include <mutex>

#include "core/Logger.h"

namespace ThreatOne::Fleet {

enum class DeploymentStatus {
    Planned,
    InProgress,
    Paused,
    Completed,
    RolledBack,
    Failed
};

struct RolloutStage {
    int stageNumber = 0;
    std::vector<std::string> endpointIds;
    int successCount = 0;
    int failureCount = 0;
    bool completed = false;
};

struct RolloutConfig {
    int stages = 3;
    int batchSize = 10;
    std::chrono::seconds delayBetweenBatches{30};
    double autoRollbackOnFailurePercent = 50.0;
};

struct DeploymentInfo {
    std::string id;
    std::string version;
    std::string previousVersion;
    std::vector<std::string> targetEndpoints;
    DeploymentStatus status = DeploymentStatus::Planned;
    RolloutConfig config;
    std::vector<RolloutStage> stages;
    int currentStage = 0;
    std::chrono::system_clock::time_point startedAt;
    std::chrono::system_clock::time_point completedAt;
    std::string rollbackVersion;
};

struct EndpointVersion {
    std::string endpointId;
    std::string version;
    std::chrono::system_clock::time_point updatedAt;
};

struct VersionDistribution {
    std::string version;
    int count = 0;
    double percentage = 0.0;
};

class IDeploymentManager {
public:
    virtual ~IDeploymentManager() = default;

    virtual std::string createDeployment(const std::string& version,
                                          const std::vector<std::string>& targetEndpoints,
                                          const RolloutConfig& config = {}) = 0;
    virtual bool startRollout(const std::string& deploymentId) = 0;
    virtual bool pauseRollout(const std::string& deploymentId) = 0;
    virtual bool resumeRollout(const std::string& deploymentId) = 0;
    virtual bool rollback(const std::string& deploymentId) = 0;

    virtual std::optional<DeploymentInfo> getDeploymentStatus(const std::string& deploymentId) const = 0;
    virtual std::vector<DeploymentInfo> getDeployments() const = 0;
    virtual std::vector<VersionDistribution> getVersionDistribution() const = 0;

    // Simulate stage completion for testing
    virtual bool advanceStage(const std::string& deploymentId, int successes, int failures) = 0;

    virtual void setEndpointVersion(const std::string& endpointId, const std::string& version) = 0;
    virtual std::optional<std::string> getEndpointVersion(const std::string& endpointId) const = 0;
};

class DeploymentManager : public IDeploymentManager {
public:
    DeploymentManager();
    ~DeploymentManager() override = default;

    std::string createDeployment(const std::string& version,
                                  const std::vector<std::string>& targetEndpoints,
                                  const RolloutConfig& config = {}) override;
    bool startRollout(const std::string& deploymentId) override;
    bool pauseRollout(const std::string& deploymentId) override;
    bool resumeRollout(const std::string& deploymentId) override;
    bool rollback(const std::string& deploymentId) override;

    std::optional<DeploymentInfo> getDeploymentStatus(const std::string& deploymentId) const override;
    std::vector<DeploymentInfo> getDeployments() const override;
    std::vector<VersionDistribution> getVersionDistribution() const override;

    bool advanceStage(const std::string& deploymentId, int successes, int failures) override;

    void setEndpointVersion(const std::string& endpointId, const std::string& version) override;
    std::optional<std::string> getEndpointVersion(const std::string& endpointId) const override;

private:
    std::string generateId() const;
    void buildStages(DeploymentInfo& deployment);

    mutable std::mutex mutex_;
    std::unordered_map<std::string, DeploymentInfo> deployments_;
    std::unordered_map<std::string, EndpointVersion> endpointVersions_;
    int nextId_ = 1;
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Fleet
