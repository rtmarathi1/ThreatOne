#pragma once

#include "telemetry/ITelemetryManager.h"
#include "core/Logger.h"

#include <mutex>
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace ThreatOne::Telemetry {

struct SessionInfo {
    std::string id;
    std::string startedAt;
    std::string endedAt;
    double durationSeconds = 0.0;
    uint64_t actionsPerformed = 0;
    std::vector<std::string> featuresUsed;
};

struct WorkflowStep {
    std::string featureName;
    std::string action;
    double durationMs = 0.0;
    std::string timestamp;
};

struct FeatureAnalytics {
    std::string featureName;
    uint64_t totalUses = 0;
    double averageDurationMs = 0.0;
    double totalDurationMs = 0.0;
    std::string firstUsed;
    std::string lastUsed;
};

class UsageAnalytics {
public:
    UsageAnalytics();
    ~UsageAnalytics() = default;

    // Session tracking
    std::string startSession();
    bool endSession(const std::string& sessionId);
    [[nodiscard]] std::optional<SessionInfo> getSession(const std::string& sessionId) const;
    [[nodiscard]] std::vector<SessionInfo> getActiveSessions() const;
    [[nodiscard]] std::vector<SessionInfo> getAllSessions() const;

    // Feature usage tracking
    bool trackFeatureUsage(const std::string& featureName, double durationMs);
    [[nodiscard]] std::vector<FeatureUsage> getFeatureUsageStats() const;
    [[nodiscard]] std::optional<FeatureAnalytics> getFeatureAnalytics(const std::string& featureName) const;
    [[nodiscard]] std::vector<std::string> getMostUsedFeatures(uint64_t limit = 10) const;

    // Workflow tracking
    void recordWorkflowStep(const std::string& sessionId, const std::string& feature,
                            const std::string& action, double durationMs);
    [[nodiscard]] std::vector<WorkflowStep> getWorkflowSteps(const std::string& sessionId) const;

    // Statistics
    [[nodiscard]] uint64_t getTotalSessions() const;
    [[nodiscard]] uint64_t getActiveSesionCount() const;
    [[nodiscard]] double getAverageSessionDuration() const;

private:
    std::string generateSessionId();
    std::string getCurrentTimestamp() const;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, SessionInfo> sessions_;
    std::unordered_map<std::string, FeatureAnalytics> featureAnalytics_;
    std::unordered_map<std::string, std::vector<WorkflowStep>> workflows_;
    int nextSessionId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Telemetry
