#include "telemetry/UsageAnalytics.h"
#include <optional>
#include <mutex>

#include <algorithm>
#include <chrono>
#include <sstream>

namespace ThreatOne::Telemetry {

UsageAnalytics::UsageAnalytics()
    : logger_(Core::Logger::instance().getModuleLogger("UsageAnalytics")) {
    logger_.info("UsageAnalytics initialized");
}

std::string UsageAnalytics::generateSessionId() {
    return "SESS-" + std::to_string(nextSessionId_++);
}

std::string UsageAnalytics::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << time;
    return oss.str();
}

std::string UsageAnalytics::startSession() {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = generateSessionId();
    SessionInfo session;
    session.id = id;
    session.startedAt = getCurrentTimestamp();
    sessions_[id] = session;
    logger_.info("Started usage session: {}", id);
    return id;
}

bool UsageAnalytics::endSession(const std::string& sessionId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = sessions_.find(sessionId);
    if (it == sessions_.end()) {
        return false;
    }

    if (!it->second.endedAt.empty()) {
        return false;  // Already ended
    }

    it->second.endedAt = getCurrentTimestamp();
    // Calculate approximate duration
    it->second.durationSeconds = 60.0;  // Simulated duration
    logger_.info("Ended session: {}", sessionId);
    return true;
}

std::optional<SessionInfo> UsageAnalytics::getSession(const std::string& sessionId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = sessions_.find(sessionId);
    if (it == sessions_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<SessionInfo> UsageAnalytics::getActiveSessions() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<SessionInfo> active;
    for (const auto& [id, session] : sessions_) {
        if (session.endedAt.empty()) {
            active.push_back(session);
        }
    }
    return active;
}

std::vector<SessionInfo> UsageAnalytics::getAllSessions() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<SessionInfo> result;
    result.reserve(sessions_.size());
    for (const auto& [id, session] : sessions_) {
        result.push_back(session);
    }
    return result;
}

bool UsageAnalytics::trackFeatureUsage(const std::string& featureName, double durationMs) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = featureAnalytics_.find(featureName);
    if (it == featureAnalytics_.end()) {
        FeatureAnalytics analytics;
        analytics.featureName = featureName;
        analytics.totalUses = 1;
        analytics.averageDurationMs = durationMs;
        analytics.totalDurationMs = durationMs;
        analytics.firstUsed = getCurrentTimestamp();
        analytics.lastUsed = getCurrentTimestamp();
        featureAnalytics_[featureName] = analytics;
    } else {
        auto& analytics = it->second;
        analytics.totalUses++;
        analytics.totalDurationMs += durationMs;
        analytics.averageDurationMs = analytics.totalDurationMs / static_cast<double>(analytics.totalUses);
        analytics.lastUsed = getCurrentTimestamp();
    }

    return true;
}

std::vector<FeatureUsage> UsageAnalytics::getFeatureUsageStats() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<FeatureUsage> result;
    for (const auto& [name, analytics] : featureAnalytics_) {
        FeatureUsage usage;
        usage.featureName = analytics.featureName;
        usage.useCount = analytics.totalUses;
        usage.lastUsed = analytics.lastUsed;
        usage.averageDurationMs = analytics.averageDurationMs;
        result.push_back(usage);
    }
    return result;
}

std::optional<FeatureAnalytics> UsageAnalytics::getFeatureAnalytics(const std::string& featureName) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = featureAnalytics_.find(featureName);
    if (it == featureAnalytics_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<std::string> UsageAnalytics::getMostUsedFeatures(uint64_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<std::pair<std::string, uint64_t>> sorted;
    for (const auto& [name, analytics] : featureAnalytics_) {
        sorted.emplace_back(name, analytics.totalUses);
    }

    std::sort(sorted.begin(), sorted.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    std::vector<std::string> result;
    for (uint64_t i = 0; i < std::min(limit, static_cast<uint64_t>(sorted.size())); ++i) {
        result.push_back(sorted[i].first);
    }
    return result;
}

void UsageAnalytics::recordWorkflowStep(const std::string& sessionId, const std::string& feature,
                                          const std::string& action, double durationMs) {
    std::lock_guard<std::mutex> lock(mutex_);

    WorkflowStep step;
    step.featureName = feature;
    step.action = action;
    step.durationMs = durationMs;
    step.timestamp = getCurrentTimestamp();

    workflows_[sessionId].push_back(step);

    // Also update session info
    auto it = sessions_.find(sessionId);
    if (it != sessions_.end()) {
        it->second.actionsPerformed++;
        auto& features = it->second.featuresUsed;
        if (std::find(features.begin(), features.end(), feature) == features.end()) {
            features.push_back(feature);
        }
    }
}

std::vector<WorkflowStep> UsageAnalytics::getWorkflowSteps(const std::string& sessionId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = workflows_.find(sessionId);
    if (it == workflows_.end()) {
        return {};
    }
    return it->second;
}

uint64_t UsageAnalytics::getTotalSessions() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.size();
}

uint64_t UsageAnalytics::getActiveSesionCount() const {
    std::lock_guard<std::mutex> lock(mutex_);

    uint64_t count = 0;
    for (const auto& [id, session] : sessions_) {
        if (session.endedAt.empty()) {
            ++count;
        }
    }
    return count;
}

double UsageAnalytics::getAverageSessionDuration() const {
    std::lock_guard<std::mutex> lock(mutex_);

    double total = 0.0;
    uint64_t count = 0;
    for (const auto& [id, session] : sessions_) {
        if (!session.endedAt.empty()) {
            total += session.durationSeconds;
            ++count;
        }
    }

    if (count == 0) return 0.0;
    return total / static_cast<double>(count);
}

} // namespace ThreatOne::Telemetry
