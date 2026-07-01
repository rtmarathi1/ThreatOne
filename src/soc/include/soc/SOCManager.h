#pragma once

#include "soc/ISOCManager.h"
#include "core/Logger.h"

#include <mutex>
#include <map>
#include <atomic>

namespace ThreatOne::SOC {

class SOCManager : public ISOCManager {
public:
    SOCManager();
    ~SOCManager() override = default;

    // Case management
    std::string createCase(const CaseInfo& caseInfo) override;
    bool assignCase(const std::string& caseId, const std::string& analystId) override;
    bool escalate(const std::string& caseId, const std::string& reason) override;
    bool updateCaseStatus(const std::string& caseId, CaseStatus status) override;
    [[nodiscard]] WorkflowInfo getWorkflow(const std::string& caseId) override;
    [[nodiscard]] SOCMetrics getMetrics() override;

    // Evidence management
    std::string addEvidence(const std::string& caseId, const EvidenceItem& evidence) override;
    [[nodiscard]] std::vector<EvidenceItem> getEvidence(const std::string& caseId) override;

    // Playbook management
    std::string createPlaybook(const Playbook& playbook) override;
    [[nodiscard]] std::vector<Playbook> getPlaybooks() override;
    std::string executePlaybook(const std::string& playbookId, const std::string& caseId) override;
    [[nodiscard]] PlaybookExecution getPlaybookExecution(const std::string& executionId) override;

    // Shift management
    std::string createShift(const ShiftInfo& shift) override;
    [[nodiscard]] std::vector<ShiftInfo> getShifts() override;
    std::string addHandoffNote(const HandoffNote& note) override;
    [[nodiscard]] std::vector<HandoffNote> getHandoffNotes(const std::string& shiftId) override;

    // Ticket integration
    std::string createTicket(const TicketInfo& ticket) override;
    bool syncTicket(const std::string& ticketId) override;
    [[nodiscard]] std::vector<TicketInfo> getTickets(const std::string& caseId) override;

private:
    mutable std::mutex mutex_;
    std::map<std::string, CaseInfo> cases_;
    std::map<std::string, std::vector<EvidenceItem>> evidence_;
    std::map<std::string, Playbook> playbooks_;
    std::map<std::string, PlaybookExecution> executions_;
    std::map<std::string, ShiftInfo> shifts_;
    std::map<std::string, std::vector<HandoffNote>> handoffNotes_;
    std::map<std::string, TicketInfo> tickets_;

    std::atomic<int> nextCaseId_{1};
    std::atomic<int> nextEvidenceId_{1};
    std::atomic<int> nextPlaybookId_{1};
    std::atomic<int> nextExecutionId_{1};
    std::atomic<int> nextShiftId_{1};
    std::atomic<int> nextHandoffId_{1};
    std::atomic<int> nextTicketId_{1};

    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::SOC
