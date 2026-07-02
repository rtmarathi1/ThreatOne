#pragma once

#include "siem/ISIEMEngine.h"
#include "core/Logger.h"

#include <mutex>
#include <string>
#include <vector>
#include <map>
#include <atomic>
#include <chrono>

namespace ThreatOne::SIEM {

class AlertEngine {
public:
    AlertEngine();
    ~AlertEngine() = default;

    // Alert creation
    std::string createAlert(const SIEMAlert& alert);

    // Alert retrieval
    [[nodiscard]] std::vector<SIEMAlert> getAlerts() const;
    [[nodiscard]] SIEMAlert getAlert(const std::string& alertId) const;
    [[nodiscard]] std::vector<SIEMAlert> getAlertsByRule(const std::string& ruleId) const;
    [[nodiscard]] std::vector<SIEMAlert> getAlertsBySeverity(const std::string& severity) const;

    // Alert management
    bool acknowledgeAlert(const std::string& alertId);
    bool resolveAlert(const std::string& alertId);
    bool dismissAlert(const std::string& alertId);

    // Deduplication - check if a similar alert already exists
    [[nodiscard]] bool isDuplicate(const SIEMAlert& alert) const;

    // Stats
    [[nodiscard]] size_t getAlertCount() const;
    [[nodiscard]] size_t getActiveAlertCount() const;

private:
    std::string generateAlertId();

    mutable std::mutex mutex_;
    std::map<std::string, SIEMAlert> alerts_;
    std::atomic<int> nextAlertId_{1};

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::SIEM
