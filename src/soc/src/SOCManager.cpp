#include "soc/SOCManager.h"

namespace ThreatOne::SOC {

SOCManager::SOCManager()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("SOCManager")) {
    logger_.info("SOCManager initialized (stub)");
}

std::string SOCManager::createCase(const CaseInfo& caseInfo) {
    logger_.info("createCase called: {}", caseInfo.title);
    return "CASE-001";
}

bool SOCManager::assignCase(const std::string& caseId, const std::string& analystId) {
    logger_.info("assignCase called: case={}, analyst={}", caseId, analystId);
    return true;
}

bool SOCManager::escalate(const std::string& caseId, const std::string& reason) {
    logger_.info("escalate called: case={}, reason={}", caseId, reason);
    return true;
}

WorkflowInfo SOCManager::getWorkflow(const std::string& caseId) {
    logger_.info("getWorkflow called: {}", caseId);
    return {"WF-001", "Standard Investigation", {"Triage", "Investigate", "Contain", "Remediate", "Close"}, "Triage"};
}

SOCMetrics SOCManager::getMetrics() {
    logger_.info("getMetrics called");
    return {5, 120, 15.5, 45.0, 3};
}

std::vector<ShiftInfo> SOCManager::getShifts() {
    logger_.info("getShifts called");
    return {};
}

} // namespace ThreatOne::SOC
