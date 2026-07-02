#include "soc/EvidenceCollector.h"
#include <mutex>

#include <algorithm>

namespace ThreatOne::SOC {

EvidenceCollector::EvidenceCollector()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("EvidenceCollector")) {
    logger_.info("EvidenceCollector initialized");
}

std::string EvidenceCollector::addEvidence(const std::string& caseId, const EvidenceItem& evidence) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = "EV-" + std::to_string(nextEvidenceId_++);
    EvidenceItem stored = evidence;
    stored.id = id;
    stored.caseId = caseId;
    evidenceByCase_[caseId].push_back(stored);
    evidenceById_[id] = stored;

    // Record initial chain of custody entry
    ChainOfCustodyEntry entry;
    entry.evidenceId = id;
    entry.action = "collected";
    entry.performer = evidence.addedBy;
    entry.timestamp = "now";
    entry.notes = "Evidence collected for case " + caseId;
    custodyChains_[id].push_back(entry);

    logger_.info("Added evidence {} to case {}: type={}", id, caseId, evidence.type);
    return id;
}

std::vector<EvidenceItem> EvidenceCollector::getEvidence(const std::string& caseId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = evidenceByCase_.find(caseId);
    if (it != evidenceByCase_.end()) {
        return it->second;
    }
    return {};
}

EvidenceItem EvidenceCollector::getEvidenceById(const std::string& evidenceId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = evidenceById_.find(evidenceId);
    if (it != evidenceById_.end()) {
        return it->second;
    }
    return {};
}

bool EvidenceCollector::removeEvidence(const std::string& evidenceId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = evidenceById_.find(evidenceId);
    if (it == evidenceById_.end()) {
        return false;
    }

    std::string caseId = it->second.caseId;
    evidenceById_.erase(it);

    // Remove from case collection
    auto caseIt = evidenceByCase_.find(caseId);
    if (caseIt != evidenceByCase_.end()) {
        auto& items = caseIt->second;
        items.erase(std::remove_if(items.begin(), items.end(),
            [&evidenceId](const EvidenceItem& e) { return e.id == evidenceId; }),
            items.end());
    }

    logger_.info("Removed evidence {}", evidenceId);
    return true;
}

bool EvidenceCollector::addCustodyEntry(const std::string& evidenceId, const ChainOfCustodyEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (evidenceById_.find(evidenceId) == evidenceById_.end()) {
        return false;
    }

    ChainOfCustodyEntry stored = entry;
    stored.evidenceId = evidenceId;
    custodyChains_[evidenceId].push_back(stored);

    logger_.info("Added custody entry for evidence {}: action={}", evidenceId, entry.action);
    return true;
}

std::vector<ChainOfCustodyEntry> EvidenceCollector::getCustodyChain(const std::string& evidenceId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = custodyChains_.find(evidenceId);
    if (it != custodyChains_.end()) {
        return it->second;
    }
    return {};
}

bool EvidenceCollector::evidenceExists(const std::string& evidenceId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return evidenceById_.find(evidenceId) != evidenceById_.end();
}

size_t EvidenceCollector::getEvidenceCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return evidenceById_.size();
}

size_t EvidenceCollector::getEvidenceCountForCase(const std::string& caseId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = evidenceByCase_.find(caseId);
    if (it != evidenceByCase_.end()) {
        return it->second.size();
    }
    return 0;
}

std::vector<EvidenceItem> EvidenceCollector::getEvidenceByType(const std::string& type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<EvidenceItem> result;
    for (const auto& [id, item] : evidenceById_) {
        if (item.type == type) {
            result.push_back(item);
        }
    }
    return result;
}

} // namespace ThreatOne::SOC
