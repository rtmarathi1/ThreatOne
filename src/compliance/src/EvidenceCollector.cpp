#include "compliance/EvidenceCollector.h"

#include <algorithm>
#include <chrono>
#include <sstream>

namespace ThreatOne::Compliance {

EvidenceCollector::EvidenceCollector()
    : logger_("EvidenceCollector") {
    logger_.info("EvidenceCollector initialized");
}

std::string EvidenceCollector::generateId() {
    std::ostringstream oss;
    oss << "ev-" << nextId_.fetch_add(1);
    return oss.str();
}

std::string EvidenceCollector::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::ctime(&time);
    std::string result = oss.str();
    if (!result.empty() && result.back() == '\n') {
        result.pop_back();
    }
    return result;
}

ThreatOne::Core::Result<EvidenceRecord> EvidenceCollector::addEvidence(
    const std::string& controlId,
    Framework framework,
    EvidenceType type,
    const std::string& title,
    const std::string& content) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (controlId.empty()) {
        return ThreatOne::Core::Result<EvidenceRecord>::err(
            ThreatOne::Core::Error("Control ID cannot be empty",
                                   ThreatOne::Core::ErrorCategory::Validation));
    }

    if (title.empty()) {
        return ThreatOne::Core::Result<EvidenceRecord>::err(
            ThreatOne::Core::Error("Evidence title cannot be empty",
                                   ThreatOne::Core::ErrorCategory::Validation));
    }

    EvidenceRecord record;
    record.id = generateId();
    record.controlId = controlId;
    record.framework = framework;
    record.type = type;
    record.title = title;
    record.content = content;
    record.collectedAt = getCurrentTimestamp();
    record.verified = false;

    evidence_[record.id] = record;
    logger_.info("Added evidence {} for control {}", record.id, controlId);

    return ThreatOne::Core::Result<EvidenceRecord>::ok(record);
}

std::optional<EvidenceRecord> EvidenceCollector::getEvidence(const std::string& evidenceId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = evidence_.find(evidenceId);
    if (it == evidence_.end()) return std::nullopt;
    return it->second;
}

std::vector<EvidenceRecord> EvidenceCollector::getEvidenceForControl(const std::string& controlId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<EvidenceRecord> result;
    for (const auto& [id, record] : evidence_) {
        if (record.controlId == controlId) {
            result.push_back(record);
        }
    }
    return result;
}

std::vector<EvidenceRecord> EvidenceCollector::getEvidenceByType(EvidenceType type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<EvidenceRecord> result;
    for (const auto& [id, record] : evidence_) {
        if (record.type == type) {
            result.push_back(record);
        }
    }
    return result;
}

std::vector<EvidenceRecord> EvidenceCollector::getEvidenceByFramework(Framework framework) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<EvidenceRecord> result;
    for (const auto& [id, record] : evidence_) {
        if (record.framework == framework) {
            result.push_back(record);
        }
    }
    return result;
}

ThreatOne::Core::Result<void> EvidenceCollector::verifyEvidence(const std::string& evidenceId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = evidence_.find(evidenceId);
    if (it == evidence_.end()) {
        return ThreatOne::Core::Result<void>::err(
            ThreatOne::Core::Error("Evidence not found: " + evidenceId,
                                   ThreatOne::Core::ErrorCategory::Validation));
    }
    it->second.verified = true;
    logger_.info("Evidence {} verified", evidenceId);
    return ThreatOne::Core::Result<void>::ok();
}

ThreatOne::Core::Result<void> EvidenceCollector::removeEvidence(const std::string& evidenceId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = evidence_.find(evidenceId);
    if (it == evidence_.end()) {
        return ThreatOne::Core::Result<void>::err(
            ThreatOne::Core::Error("Evidence not found: " + evidenceId,
                                   ThreatOne::Core::ErrorCategory::Validation));
    }
    evidence_.erase(it);
    logger_.info("Evidence {} removed", evidenceId);
    return ThreatOne::Core::Result<void>::ok();
}

size_t EvidenceCollector::getEvidenceCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return evidence_.size();
}

void EvidenceCollector::clearAll() {
    std::lock_guard<std::mutex> lock(mutex_);
    evidence_.clear();
    logger_.info("All evidence cleared");
}

} // namespace ThreatOne::Compliance
