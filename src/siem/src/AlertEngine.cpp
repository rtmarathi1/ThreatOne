#include "siem/AlertEngine.h"
#include <mutex>

#include <algorithm>

namespace ThreatOne::SIEM {

AlertEngine::AlertEngine()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("AlertEngine")) {
    logger_.info("AlertEngine initialized");
}

std::string AlertEngine::generateAlertId() {
    return "ALERT-" + std::to_string(nextAlertId_++);
}

std::string AlertEngine::createAlert(const SIEMAlert& alert) {
    std::lock_guard<std::mutex> lock(mutex_);

    SIEMAlert stored = alert;
    if (stored.id.empty()) {
        stored.id = generateAlertId();
    }
    alerts_[stored.id] = stored;
    logger_.info("Created alert: id={}, title={}", stored.id, stored.title);

    // Publish SecurityEvent via EventBus
    Core::SecurityEvent::Severity severity = Core::SecurityEvent::Severity::Medium;
    if (stored.severity == "critical") severity = Core::SecurityEvent::Severity::Critical;
    else if (stored.severity == "high") severity = Core::SecurityEvent::Severity::High;
    else if (stored.severity == "low") severity = Core::SecurityEvent::Severity::Low;
    else if (stored.severity == "info") severity = Core::SecurityEvent::Severity::Info;

    Core::SecurityEvent event(
        Core::SecurityEvent::Type::ThreatDetected,
        severity,
        "SIEM Alert: " + stored.title);
    event.setSource("AlertEngine");
    event.setData("alertId", stored.id);
    event.setData("ruleId", stored.ruleId);
    Core::EventBus::instance().publish(event);

    return stored.id;
}

std::vector<SIEMAlert> AlertEngine::getAlerts() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<SIEMAlert> result;
    result.reserve(alerts_.size());
    for (const auto& [id, alert] : alerts_) {
        result.push_back(alert);
    }
    return result;
}

SIEMAlert AlertEngine::getAlert(const std::string& alertId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = alerts_.find(alertId);
    if (it != alerts_.end()) {
        return it->second;
    }
    return {};
}

std::vector<SIEMAlert> AlertEngine::getAlertsByRule(const std::string& ruleId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<SIEMAlert> result;
    for (const auto& [id, alert] : alerts_) {
        if (alert.ruleId == ruleId) {
            result.push_back(alert);
        }
    }
    return result;
}

std::vector<SIEMAlert> AlertEngine::getAlertsBySeverity(const std::string& severity) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<SIEMAlert> result;
    for (const auto& [id, alert] : alerts_) {
        if (alert.severity == severity) {
            result.push_back(alert);
        }
    }
    return result;
}

bool AlertEngine::acknowledgeAlert(const std::string& alertId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = alerts_.find(alertId);
    if (it != alerts_.end()) {
        // Mark as acknowledged in description
        it->second.description += " [ACKNOWLEDGED]";
        return true;
    }
    return false;
}

bool AlertEngine::resolveAlert(const std::string& alertId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = alerts_.find(alertId);
    if (it != alerts_.end()) {
        it->second.description += " [RESOLVED]";
        return true;
    }
    return false;
}

bool AlertEngine::dismissAlert(const std::string& alertId) {
    std::lock_guard<std::mutex> lock(mutex_);
    return alerts_.erase(alertId) > 0;
}

bool AlertEngine::isDuplicate(const SIEMAlert& alert) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [id, existing] : alerts_) {
        if (existing.ruleId == alert.ruleId &&
            existing.title == alert.title &&
            existing.severity == alert.severity) {
            return true;
        }
    }
    return false;
}

size_t AlertEngine::getAlertCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return alerts_.size();
}

size_t AlertEngine::getActiveAlertCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& [id, alert] : alerts_) {
        if (alert.description.find("[RESOLVED]") == std::string::npos) {
            count++;
        }
    }
    return count;
}

} // namespace ThreatOne::SIEM
