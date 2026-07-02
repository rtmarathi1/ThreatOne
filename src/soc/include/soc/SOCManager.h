#pragma once

#include "soc/ISOCManager.h"
#include "soc/CaseManager.h"
#include "soc/IncidentManager.h"
#include "soc/PlaybookEngine.h"
#include "soc/WorkflowAutomation.h"
#include "soc/EvidenceCollector.h"
#include "soc/TimelineBuilder.h"
#include "soc/SOCDashboardData.h"
#include "soc/AlertTriage.h"
#include "core/Logger.h"

#include <mutex>
#include <memory>
#include <string>
#include <vector>

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

    // Access to sub-components for advanced usage
    [[nodiscard]] CaseManager& getCaseManager() { return *caseManager_; }
    [[nodiscard]] IncidentManager& getIncidentManager() { return *incidentManager_; }
    [[nodiscard]] PlaybookEngine& getPlaybookEngine() { return *playbookEngine_; }
    [[nodiscard]] WorkflowAutomation& getWorkflowAutomation() { return *workflowAutomation_; }
    [[nodiscard]] EvidenceCollector& getEvidenceCollector() { return *evidenceCollector_; }
    [[nodiscard]] TimelineBuilder& getTimelineBuilder() { return *timelineBuilder_; }
    [[nodiscard]] SOCDashboardData& getSOCDashboardData() { return *dashboardData_; }
    [[nodiscard]] AlertTriage& getAlertTriage() { return *alertTriage_; }

private:
    // Sub-components
    std::shared_ptr<CaseManager> caseManager_;
    std::shared_ptr<IncidentManager> incidentManager_;
    std::shared_ptr<PlaybookEngine> playbookEngine_;
    std::shared_ptr<WorkflowAutomation> workflowAutomation_;
    std::shared_ptr<EvidenceCollector> evidenceCollector_;
    std::shared_ptr<TimelineBuilder> timelineBuilder_;
    std::shared_ptr<SOCDashboardData> dashboardData_;
    std::shared_ptr<AlertTriage> alertTriage_;

    // Shift and ticket data (kept locally as they don't need own components yet)
    mutable std::mutex mutex_;
    std::map<std::string, ShiftInfo> shifts_;
    std::map<std::string, std::vector<HandoffNote>> handoffNotes_;
    std::map<std::string, TicketInfo> tickets_;

    int nextShiftId_ = 1;
    int nextHandoffId_ = 1;
    int nextTicketId_ = 1;

    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::SOC
