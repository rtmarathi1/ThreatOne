#pragma once

#include <memory>

#include "compliance/IComplianceEngine.h"
#include "compliance/ComplianceFramework.h"
#include "compliance/ComplianceScanner.h"
#include "compliance/ComplianceScoring.h"
#include "compliance/EvidenceCollector.h"
#include "compliance/RemediationTracker.h"
#include "core/Logger.h"
#include <string>
#include <vector>

namespace ThreatOne::Compliance {

class ComplianceEngine : public IComplianceEngine {
public:
    ComplianceEngine();
    ~ComplianceEngine() override = default;

    // IComplianceEngine interface
    AuditResult runAudit(Framework framework) override;
    std::vector<FrameworkInfo> getFrameworks() override;
    std::vector<ControlInfo> getControls(Framework framework) override;
    double getComplianceScore(Framework framework) override;
    std::string generateReport(Framework framework) override;

    // Access sub-components
    ComplianceFramework& getFrameworkManager() { return framework_; }
    ComplianceScanner& getScanner() { return scanner_; }
    ComplianceScoring& getScoring() { return scoring_; }
    EvidenceCollector& getEvidenceCollector() { return evidence_; }
    RemediationTracker& getRemediationTracker() { return remediation_; }

private:
    ComplianceFramework framework_;
    ComplianceScanner scanner_;
    ComplianceScoring scoring_;
    EvidenceCollector evidence_;
    RemediationTracker remediation_;
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Compliance
