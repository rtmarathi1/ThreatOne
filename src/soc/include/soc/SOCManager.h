#pragma once

#include "soc/ISOCManager.h"
#include "core/Logger.h"

namespace ThreatOne::SOC {

class SOCManager : public ISOCManager {
public:
    SOCManager();
    ~SOCManager() override = default;

    std::string createCase(const CaseInfo& caseInfo) override;
    bool assignCase(const std::string& caseId, const std::string& analystId) override;
    bool escalate(const std::string& caseId, const std::string& reason) override;
    WorkflowInfo getWorkflow(const std::string& caseId) override;
    SOCMetrics getMetrics() override;
    std::vector<ShiftInfo> getShifts() override;

private:
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::SOC
