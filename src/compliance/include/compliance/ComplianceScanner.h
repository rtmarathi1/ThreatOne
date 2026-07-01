#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>

#include "compliance/IComplianceEngine.h"
#include "compliance/ComplianceFramework.h"
#include "core/Logger.h"
#include "core/Error.h"

namespace ThreatOne::Compliance {

// Configurable system state for scanning
struct SystemState {
    std::map<std::string, std::string> configurations;
    std::vector<std::string> enabledFeatures;
    std::vector<std::string> installedPolicies;
};

class ComplianceScanner {
public:
    explicit ComplianceScanner(ComplianceFramework& framework);
    ~ComplianceScanner() = default;

    // Scan a framework against the system state
    [[nodiscard]] ThreatOne::Core::Result<std::vector<ComplianceFinding>> scan(
        Framework framework, const SystemState& state);

    // Scan a specific control
    [[nodiscard]] ComplianceFinding scanControl(
        const ControlInfo& control, const SystemState& state);

    // Get all findings from the last scan
    [[nodiscard]] std::vector<ComplianceFinding> getFindings() const;

    // Get findings filtered by status
    [[nodiscard]] std::vector<ComplianceFinding> getFindingsByStatus(FindingStatus status) const;

    // Get findings for a specific framework
    [[nodiscard]] std::vector<ComplianceFinding> getFindingsByFramework(Framework framework) const;

    // Clear all findings
    void clearFindings();

    // Get total scan count
    [[nodiscard]] size_t getScanCount() const;

private:
    [[nodiscard]] std::string generateFindingId();
    [[nodiscard]] std::string getCurrentTimestamp() const;
    [[nodiscard]] FindingStatus evaluateControl(const ControlInfo& control, const SystemState& state) const;
    [[nodiscard]] FindingSeverity determineSeverity(const ControlInfo& control) const;

    ComplianceFramework& framework_;
    mutable std::mutex mutex_;
    std::vector<ComplianceFinding> findings_;
    std::atomic<int> nextFindingId_{1};
    std::atomic<size_t> scanCount_{0};
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Compliance
