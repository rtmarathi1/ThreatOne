#pragma once

#include "soc/ISOCManager.h"
#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>

namespace ThreatOne::SOC {

struct ChainOfCustodyEntry {
    std::string evidenceId;
    std::string action;  // "collected", "transferred", "analyzed", "stored"
    std::string performer;
    std::string timestamp;
    std::string notes;
};

class EvidenceCollector {
public:
    EvidenceCollector();
    ~EvidenceCollector() = default;

    // Evidence management
    std::string addEvidence(const std::string& caseId, const EvidenceItem& evidence);
    [[nodiscard]] std::vector<EvidenceItem> getEvidence(const std::string& caseId) const;
    [[nodiscard]] EvidenceItem getEvidenceById(const std::string& evidenceId) const;
    bool removeEvidence(const std::string& evidenceId);

    // Chain of custody
    bool addCustodyEntry(const std::string& evidenceId, const ChainOfCustodyEntry& entry);
    [[nodiscard]] std::vector<ChainOfCustodyEntry> getCustodyChain(const std::string& evidenceId) const;

    // Queries
    [[nodiscard]] bool evidenceExists(const std::string& evidenceId) const;
    [[nodiscard]] size_t getEvidenceCount() const;
    [[nodiscard]] size_t getEvidenceCountForCase(const std::string& caseId) const;
    [[nodiscard]] std::vector<EvidenceItem> getEvidenceByType(const std::string& type) const;

private:
    mutable std::mutex mutex_;
    std::map<std::string, std::vector<EvidenceItem>> evidenceByCase_;
    std::map<std::string, EvidenceItem> evidenceById_;
    std::map<std::string, std::vector<ChainOfCustodyEntry>> custodyChains_;
    int nextEvidenceId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::SOC
