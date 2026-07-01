#pragma once

#include <string>
#include <vector>

namespace ThreatOne::SOC {

struct CaseInfo {
    std::string id;
    std::string title;
    std::string description;
    std::string severity;
    std::string status;
    std::string assignee;
    std::string createdAt;
};

struct WorkflowInfo {
    std::string id;
    std::string name;
    std::vector<std::string> steps;
    std::string currentStep;
};

struct SOCMetrics {
    uint64_t openCases = 0;
    uint64_t closedCases = 0;
    double meanTimeToDetect = 0.0;
    double meanTimeToRespond = 0.0;
    uint64_t activeAnalysts = 0;
};

struct ShiftInfo {
    std::string id;
    std::string name;
    std::string startTime;
    std::string endTime;
    std::vector<std::string> analysts;
};

class ISOCManager {
public:
    virtual ~ISOCManager() = default;

    virtual std::string createCase(const CaseInfo& caseInfo) = 0;
    virtual bool assignCase(const std::string& caseId, const std::string& analystId) = 0;
    virtual bool escalate(const std::string& caseId, const std::string& reason) = 0;
    virtual WorkflowInfo getWorkflow(const std::string& caseId) = 0;
    virtual SOCMetrics getMetrics() = 0;
    virtual std::vector<ShiftInfo> getShifts() = 0;
};

} // namespace ThreatOne::SOC
