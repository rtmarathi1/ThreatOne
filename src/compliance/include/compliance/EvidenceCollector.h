#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>
#include <optional>

#include "compliance/IComplianceEngine.h"
#include "core/Logger.h"
#include "core/Error.h"

namespace ThreatOne::Compliance {

class EvidenceCollector {
public:
    EvidenceCollector();
    ~EvidenceCollector() = default;

    // Add evidence for a control
    [[nodiscard]] ThreatOne::Core::Result<EvidenceRecord> addEvidence(
        const std::string& controlId,
        Framework framework,
        EvidenceType type,
        const std::string& title,
        const std::string& content);

    // Get evidence by ID
    [[nodiscard]] std::optional<EvidenceRecord> getEvidence(const std::string& evidenceId) const;

    // Get all evidence for a control
    [[nodiscard]] std::vector<EvidenceRecord> getEvidenceForControl(const std::string& controlId) const;

    // Get all evidence of a specific type
    [[nodiscard]] std::vector<EvidenceRecord> getEvidenceByType(EvidenceType type) const;

    // Get all evidence for a framework
    [[nodiscard]] std::vector<EvidenceRecord> getEvidenceByFramework(Framework framework) const;

    // Mark evidence as verified
    [[nodiscard]] ThreatOne::Core::Result<void> verifyEvidence(const std::string& evidenceId);

    // Remove evidence by ID
    [[nodiscard]] ThreatOne::Core::Result<void> removeEvidence(const std::string& evidenceId);

    // Get total evidence count
    [[nodiscard]] size_t getEvidenceCount() const;

    // Clear all evidence
    void clearAll();

private:
    [[nodiscard]] std::string generateId();
    [[nodiscard]] std::string getCurrentTimestamp() const;

    mutable std::mutex mutex_;
    std::map<std::string, EvidenceRecord> evidence_;
    std::atomic<int> nextId_{1};
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Compliance
