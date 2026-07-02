#pragma once

#include "soc/ISOCManager.h"
#include "core/Logger.h"
#include "core/EventBus.h"
#include "core/Event.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>

namespace ThreatOne::SOC {

class CaseManager {
public:
    CaseManager();
    ~CaseManager() = default;

    // Case lifecycle
    std::string createCase(const CaseInfo& caseInfo);
    bool assignCase(const std::string& caseId, const std::string& analystId);
    bool escalate(const std::string& caseId, const std::string& reason);
    bool updateCaseStatus(const std::string& caseId, CaseStatus status);

    // Case queries
    [[nodiscard]] bool caseExists(const std::string& caseId) const;
    [[nodiscard]] CaseInfo getCase(const std::string& caseId) const;
    [[nodiscard]] std::vector<CaseInfo> getAllCases() const;
    [[nodiscard]] std::vector<CaseInfo> getCasesByStatus(CaseStatus status) const;
    [[nodiscard]] std::vector<CaseInfo> getCasesByAssignee(const std::string& analystId) const;
    [[nodiscard]] size_t getCaseCount() const;

    // Analyst workload
    [[nodiscard]] std::vector<std::string> getActiveAnalysts() const;

private:
    bool isValidTransition(CaseStatus from, CaseStatus to) const;

    mutable std::mutex mutex_;
    std::map<std::string, CaseInfo> cases_;
    int nextCaseId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::SOC
