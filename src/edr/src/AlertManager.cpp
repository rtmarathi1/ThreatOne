#include "edr/AlertManager.h"

#include "core/Event.h"
#include "core/EventBus.h"

#include <algorithm>
#include <functional>
#include <chrono>
#include <mutex>
#include <string>
#include <vector>

namespace ThreatOne::EDR {

AlertManager::AlertManager()
    : logger_(Core::Logger::instance().getModuleLogger("AlertManager"))
{
    logger_.info("AlertManager initialized");
}

std::string AlertManager::generateAlert(const std::string& source, const std::string& severity,
                                         const std::string& description, const std::string& evidence) {
    std::lock_guard lock(mutex_);

    std::string dedupKey = generateDedupKey(source, description);

    // Check for deduplication
    if (isDuplicate(dedupKey)) {
        deduplicatedCount_++;
        logger_.debug("Alert deduplicated: {}", description);
        return "";
    }

    Alert alert;
    alert.id = generateId();
    alert.timestamp = std::chrono::steady_clock::now();
    alert.source = source;
    alert.severity = severity;
    alert.description = description;
    alert.evidence = evidence;
    alert.status = AlertStatus::New;
    alert.dedupKey = dedupKey;

    alerts_.push_back(alert);

    // Update dedup index with the latest timestamp for this key
    dedupIndex_[dedupKey] = alert.timestamp;

    // Evict oldest alerts if over capacity
    if (alerts_.size() > maxCapacity_) {
        // Remove the dedup entry for the evicted alert if it points to the old timestamp
        const auto& evicted = alerts_.front();
        auto dedupIt = dedupIndex_.find(evicted.dedupKey);
        if (dedupIt != dedupIndex_.end() && dedupIt->second == evicted.timestamp) {
            dedupIndex_.erase(dedupIt);
        }
        alerts_.erase(alerts_.begin());
    }

    logger_.info("Alert generated: [{}] {} - {}", severity, source, description);

    // Publish SecurityEvent to EventBus
    auto mapSeverity = [](const std::string& sev) -> Core::SecurityEvent::Severity {
        if (sev == "critical") return Core::SecurityEvent::Severity::Critical;
        if (sev == "high") return Core::SecurityEvent::Severity::High;
        if (sev == "medium") return Core::SecurityEvent::Severity::Medium;
        if (sev == "low") return Core::SecurityEvent::Severity::Low;
        return Core::SecurityEvent::Severity::Info;
    };

    Core::SecurityEvent secEvent(
        Core::SecurityEvent::Type::ThreatDetected,
        mapSeverity(severity),
        description
    );
    secEvent.setSource(source);
    Core::EventBus::instance().publish(secEvent);

    return alert.id;
}

std::vector<Alert> AlertManager::getAlerts(const AlertFilter& filter) const {
    std::lock_guard lock(mutex_);
    std::vector<Alert> result;

    for (const auto& alert : alerts_) {
        bool matches = true;

        if (filter.filterByStatus && alert.status != filter.status) {
            matches = false;
        }
        if (filter.filterBySource && alert.source != filter.source) {
            matches = false;
        }
        if (filter.filterBySeverity && alert.severity != filter.severity) {
            matches = false;
        }

        if (matches) {
            result.push_back(alert);
        }
    }

    // Sort by severity (critical first)
    std::sort(result.begin(), result.end(), [this](const Alert& a, const Alert& b) {
        return severityToInt(a.severity) > severityToInt(b.severity);
    });

    return result;
}

bool AlertManager::acknowledgeAlert(const std::string& id) {
    std::lock_guard lock(mutex_);
    for (auto& alert : alerts_) {
        if (alert.id == id) {
            alert.status = AlertStatus::Acknowledged;
            logger_.debug("Alert acknowledged: {}", id);
            return true;
        }
    }
    return false;
}

bool AlertManager::resolveAlert(const std::string& id) {
    std::lock_guard lock(mutex_);
    for (auto& alert : alerts_) {
        if (alert.id == id) {
            alert.status = AlertStatus::Resolved;
            logger_.debug("Alert resolved: {}", id);
            return true;
        }
    }
    return false;
}

AlertStats AlertManager::getAlertStats() const {
    std::lock_guard lock(mutex_);
    AlertStats stats;
    stats.totalAlerts = alerts_.size();
    stats.deduplicated = deduplicatedCount_;

    for (const auto& alert : alerts_) {
        switch (alert.status) {
            case AlertStatus::New:
                stats.newAlerts++;
                break;
            case AlertStatus::Acknowledged:
                stats.acknowledgedAlerts++;
                break;
            case AlertStatus::Resolved:
                stats.resolvedAlerts++;
                break;
        }
    }

    return stats;
}

void AlertManager::setDeduplicationWindow(std::chrono::seconds window) {
    dedupWindow_ = window;
}

void AlertManager::setMaxCapacity(size_t maxCapacity) {
    std::lock_guard lock(mutex_);
    maxCapacity_ = maxCapacity;
    // Evict oldest if already over the new limit
    while (alerts_.size() > maxCapacity_) {
        const auto& evicted = alerts_.front();
        auto dedupIt = dedupIndex_.find(evicted.dedupKey);
        if (dedupIt != dedupIndex_.end() && dedupIt->second == evicted.timestamp) {
            dedupIndex_.erase(dedupIt);
        }
        alerts_.erase(alerts_.begin());
    }
}

void AlertManager::clear() {
    std::lock_guard lock(mutex_);
    alerts_.clear();
    dedupIndex_.clear();
    deduplicatedCount_ = 0;
}

std::string AlertManager::generateDedupKey(const std::string& source, const std::string& description) const {
    return source + "|" + description;
}

bool AlertManager::isDuplicate(const std::string& dedupKey) const {
    auto it = dedupIndex_.find(dedupKey);
    if (it != dedupIndex_.end()) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second);
        if (elapsed < dedupWindow_) {
            return true;
        }
    }
    return false;
}

std::string AlertManager::generateId() {
    return "ALERT-" + std::to_string(nextId_.fetch_add(1));
}

int AlertManager::severityToInt(const std::string& severity) const {
    if (severity == "critical") return 5;
    if (severity == "high") return 4;
    if (severity == "medium") return 3;
    if (severity == "low") return 2;
    if (severity == "info") return 1;
    return 0;
}

} // namespace ThreatOne::EDR
