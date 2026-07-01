#pragma once

#include "compliance/IComplianceEngine.h"
#include "core/Logger.h"

namespace ThreatOne::Compliance {

class ComplianceEngine : public IComplianceEngine {
public:
    ComplianceEngine();
    ~ComplianceEngine() override = default;

    AuditResult runAudit(Framework framework) override;
    std::vector<FrameworkInfo> getFrameworks() override;
    std::vector<ControlInfo> getControls(Framework framework) override;
    double getComplianceScore(Framework framework) override;
    std::string generateReport(Framework framework) override;

private:
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Compliance
