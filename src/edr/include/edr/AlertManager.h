#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <mutex>
#include <cstdint>
#include <atomic>
#include <functional>

#include "core/Logger.h"

namespace ThreatOne::EDR {

// Alert status
enum class AlertStatus {
    New,
    Acknowledged,
    Resolved
};

// Alert structure
struct Alert {
    std::string id;
    std::chrono::steady_clock::time_point timestamp;
    std::string source;
    std::string severity;     // "info", "low", "medium", "high", "critical"
    std::string description;
    std::string evidence;
    AlertStatus status = AlertStatus::New;
    std::string dedupKey;
};

// Filter for querying alerts
struct AlertFilter {
    std::string source;
    std::string severity;
    AlertStatus status = AlertStatus::New;
    bool filterByStatus = false;
    bool filterBySource = false;
    bool filterBySeverity = false;
};

// Stats about the alert system
struct AlertStats {
    size_t totalAlerts = 0;
    size_t newAlerts = 0;
    size_t acknowledgedAlerts = 0;
    size_t resolvedAlerts = 0;
    size_t deduplicated = 0;
};

class AlertManager {
public:
    AlertManager();
    ~AlertManager() = default;

    // Generate a new alert (may be deduplicated)
    std::string generateAlert(const std::string& source, const std::string& severity,
                              const std::string& description, const std::string& evidence);

    // Query alerts with optional filter
    [[nodiscard]] std::vector<Alert> getAlerts(const AlertFilter& filter = AlertFilter{}) const;

    // Acknowledge an alert by ID
    bool acknowledgeAlert(const std::string& id);

    // Resolve an alert by ID
    bool resolveAlert(const std::string& id);

    // Get statistics
    [[nodiscard]] AlertStats getAlertStats() const;

    // Configure deduplication window
    void setDeduplicationWindow(std::chrono::seconds window);

    // Configure max capacity (oldest alerts evicted when full)
    void setMaxCapacity(size_t maxCapacity);

    // Clear all alerts
    void clear();

private:
    [[nodiscard]] std::string generateDedupKey(const std::string& source, const std::string& description) const;
    [[nodiscard]] bool isDuplicate(const std::string& dedupKey) const;
    [[nodiscard]] std::string generateId();
    [[nodiscard]] int severityToInt(const std::string& severity) const;

    mutable std::mutex mutex_;
    Core::ModuleLogger logger_;
    std::vector<Alert> alerts_;
    std::chrono::seconds dedupWindow_{60};
    std::atomic<uint64_t> nextId_{1};
    size_t deduplicatedCount_ = 0;
    size_t maxCapacity_ = 10000;
};

} // namespace ThreatOne::EDR
