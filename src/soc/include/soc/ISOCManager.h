#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace ThreatOne::SOC {

enum class CaseStatus {
    Open,
    Investigating,
    Escalated,
    Resolved,
    Closed
};

struct CaseInfo {
    std::string id;
    std::string title;
    std::string description;
    std::string severity;
    CaseStatus status = CaseStatus::Open;
    std::string assignee;
    std::string createdAt;
    std::string escalationReason;
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

struct EvidenceItem {
    std::string id;
    std::string caseId;
    std::string type;
    std::string description;
    std::string data;
    std::string addedAt;
    std::string addedBy;
};

struct PlaybookStep {
    std::string id;
    std::string name;
    std::string description;
    std::string actionType;
    std::unordered_map<std::string, std::string> parameters;
    std::string condition;
    bool completed = false;
};

struct Playbook {
    std::string id;
    std::string name;
    std::string description;
    std::vector<PlaybookStep> steps;
    std::string triggerCondition;
};

enum class ExecutionStatus {
    Running,
    Completed,
    Failed,
    Paused
};

struct PlaybookExecution {
    std::string id;
    std::string playbookId;
    std::string caseId;
    ExecutionStatus status = ExecutionStatus::Running;
    size_t currentStepIndex = 0;
    std::string startedAt;
    std::string completedAt;
    std::vector<std::string> results;
};

struct TicketInfo {
    std::string id;
    std::string externalId;
    std::string system;
    std::string title;
    std::string status;
    std::string url;
    std::string lastSyncAt;
    std::string caseId;
};

struct HandoffNote {
    std::string id;
    std::string fromAnalyst;
    std::string toAnalyst;
    std::string shiftId;
    std::string notes;
    std::string timestamp;
    std::vector<std::string> openCases;
};

class ISOCManager {
public:
    virtual ~ISOCManager() = default;

    // Case management
    virtual std::string createCase(const CaseInfo& caseInfo) = 0;
    virtual bool assignCase(const std::string& caseId, const std::string& analystId) = 0;
    virtual bool escalate(const std::string& caseId, const std::string& reason) = 0;
    virtual bool updateCaseStatus(const std::string& caseId, CaseStatus status) = 0;
    virtual WorkflowInfo getWorkflow(const std::string& caseId) = 0;
    virtual SOCMetrics getMetrics() = 0;

    // Evidence management
    virtual std::string addEvidence(const std::string& caseId, const EvidenceItem& evidence) = 0;
    virtual std::vector<EvidenceItem> getEvidence(const std::string& caseId) = 0;

    // Playbook management
    virtual std::string createPlaybook(const Playbook& playbook) = 0;
    virtual std::vector<Playbook> getPlaybooks() = 0;
    virtual std::string executePlaybook(const std::string& playbookId, const std::string& caseId) = 0;
    virtual PlaybookExecution getPlaybookExecution(const std::string& executionId) = 0;

    // Shift management
    virtual std::string createShift(const ShiftInfo& shift) = 0;
    virtual std::vector<ShiftInfo> getShifts() = 0;
    virtual std::string addHandoffNote(const HandoffNote& note) = 0;
    virtual std::vector<HandoffNote> getHandoffNotes(const std::string& shiftId) = 0;

    // Ticket integration
    virtual std::string createTicket(const TicketInfo& ticket) = 0;
    virtual bool syncTicket(const std::string& ticketId) = 0;
    virtual std::vector<TicketInfo> getTickets(const std::string& caseId) = 0;
};

} // namespace ThreatOne::SOC
