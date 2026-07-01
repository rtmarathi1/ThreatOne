#include "soc/SOCManager.h"

#include <algorithm>

namespace ThreatOne::SOC {

SOCManager::SOCManager()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("SOCManager")) {
    logger_.info("SOCManager initialized");
}

std::string SOCManager::createCase(const CaseInfo& caseInfo) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = "CASE-" + std::to_string(nextCaseId_++);
    CaseInfo stored = caseInfo;
    stored.id = id;
    stored.status = CaseStatus::Open;
    cases_[id] = stored;

    logger_.info("Created case: id={}, title={}", id, caseInfo.title);
    return id;
}

bool SOCManager::assignCase(const std::string& caseId, const std::string& analystId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = cases_.find(caseId);
    if (it == cases_.end()) {
        logger_.warn("assignCase failed: case {} not found", caseId);
        return false;
    }

    it->second.assignee = analystId;
    logger_.info("Assigned case {} to analyst {}", caseId, analystId);
    return true;
}

bool SOCManager::escalate(const std::string& caseId, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = cases_.find(caseId);
    if (it == cases_.end()) {
        logger_.warn("escalate failed: case {} not found", caseId);
        return false;
    }

    it->second.status = CaseStatus::Escalated;
    it->second.escalationReason = reason;
    logger_.info("Escalated case {}: {}", caseId, reason);
    return true;
}

bool SOCManager::updateCaseStatus(const std::string& caseId, CaseStatus status) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = cases_.find(caseId);
    if (it == cases_.end()) {
        logger_.warn("updateCaseStatus failed: case {} not found", caseId);
        return false;
    }

    // Validate status transitions
    CaseStatus current = it->second.status;

    // Cannot reopen a closed case
    if (current == CaseStatus::Closed) {
        logger_.warn("updateCaseStatus failed: case {} is already closed", caseId);
        return false;
    }

    // Cannot go backward from Resolved except to Closed
    if (current == CaseStatus::Resolved && status != CaseStatus::Closed) {
        logger_.warn("updateCaseStatus failed: resolved case {} can only be closed", caseId);
        return false;
    }

    it->second.status = status;
    logger_.info("Updated case {} status to {}", caseId, static_cast<int>(status));
    return true;
}

WorkflowInfo SOCManager::getWorkflow(const std::string& caseId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = cases_.find(caseId);
    if (it == cases_.end()) {
        return {};
    }

    WorkflowInfo workflow;
    workflow.id = "WF-" + caseId;
    workflow.name = "Standard Investigation";
    workflow.steps = {"Triage", "Investigate", "Contain", "Remediate", "Close"};

    switch (it->second.status) {
        case CaseStatus::Open:
            workflow.currentStep = "Triage";
            break;
        case CaseStatus::Investigating:
            workflow.currentStep = "Investigate";
            break;
        case CaseStatus::Escalated:
            workflow.currentStep = "Contain";
            break;
        case CaseStatus::Resolved:
            workflow.currentStep = "Remediate";
            break;
        case CaseStatus::Closed:
            workflow.currentStep = "Close";
            break;
    }

    return workflow;
}

SOCMetrics SOCManager::getMetrics() {
    std::lock_guard<std::mutex> lock(mutex_);

    SOCMetrics metrics;
    std::vector<std::string> activeAnalysts;

    for (const auto& [id, caseInfo] : cases_) {
        if (caseInfo.status == CaseStatus::Closed) {
            metrics.closedCases++;
        } else {
            metrics.openCases++;
        }
        if (!caseInfo.assignee.empty()) {
            if (std::find(activeAnalysts.begin(), activeAnalysts.end(), caseInfo.assignee) == activeAnalysts.end()) {
                activeAnalysts.push_back(caseInfo.assignee);
            }
        }
    }

    metrics.activeAnalysts = activeAnalysts.size();
    metrics.meanTimeToDetect = 15.5;  // Simulated value
    metrics.meanTimeToRespond = 45.0; // Simulated value

    return metrics;
}

std::string SOCManager::addEvidence(const std::string& caseId, const EvidenceItem& evidence) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = cases_.find(caseId);
    if (it == cases_.end()) {
        logger_.warn("addEvidence failed: case {} not found", caseId);
        return "";
    }

    std::string id = "EV-" + std::to_string(nextEvidenceId_++);
    EvidenceItem stored = evidence;
    stored.id = id;
    stored.caseId = caseId;
    evidence_[caseId].push_back(stored);

    logger_.info("Added evidence {} to case {}: type={}", id, caseId, evidence.type);
    return id;
}

std::vector<EvidenceItem> SOCManager::getEvidence(const std::string& caseId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = evidence_.find(caseId);
    if (it != evidence_.end()) {
        return it->second;
    }
    return {};
}

std::string SOCManager::createPlaybook(const Playbook& playbook) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = "PB-" + std::to_string(nextPlaybookId_++);
    Playbook stored = playbook;
    stored.id = id;
    playbooks_[id] = stored;

    logger_.info("Created playbook: id={}, name={}, steps={}", id, playbook.name, playbook.steps.size());
    return id;
}

std::vector<Playbook> SOCManager::getPlaybooks() {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<Playbook> result;
    result.reserve(playbooks_.size());
    for (const auto& [id, pb] : playbooks_) {
        result.push_back(pb);
    }
    return result;
}

std::string SOCManager::executePlaybook(const std::string& playbookId, const std::string& caseId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto pbIt = playbooks_.find(playbookId);
    if (pbIt == playbooks_.end()) {
        logger_.warn("executePlaybook failed: playbook {} not found", playbookId);
        return "";
    }

    auto caseIt = cases_.find(caseId);
    if (caseIt == cases_.end()) {
        logger_.warn("executePlaybook failed: case {} not found", caseId);
        return "";
    }

    std::string execId = "EXEC-" + std::to_string(nextExecutionId_++);
    PlaybookExecution execution;
    execution.id = execId;
    execution.playbookId = playbookId;
    execution.caseId = caseId;
    execution.status = ExecutionStatus::Running;
    execution.currentStepIndex = 0;
    execution.startedAt = "now";

    const auto& playbook = pbIt->second;

    // Execute each step in order
    for (size_t i = 0; i < playbook.steps.size(); ++i) {
        const auto& step = playbook.steps[i];

        // Check condition - if condition is non-empty and equals "skip", skip this step
        if (!step.condition.empty() && step.condition == "skip") {
            execution.results.push_back("Step " + step.name + ": skipped (condition not met)");
            continue;
        }

        // Execute the step
        execution.results.push_back("Step " + step.name + ": completed (" + step.actionType + ")");
        execution.currentStepIndex = i + 1;
    }

    // Mark execution as completed
    execution.status = ExecutionStatus::Completed;
    execution.completedAt = "now";
    executions_[execId] = execution;

    logger_.info("Executed playbook {} on case {}: execution={}", playbookId, caseId, execId);
    return execId;
}

PlaybookExecution SOCManager::getPlaybookExecution(const std::string& executionId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = executions_.find(executionId);
    if (it != executions_.end()) {
        return it->second;
    }
    return {};
}

std::string SOCManager::createShift(const ShiftInfo& shift) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = "SHIFT-" + std::to_string(nextShiftId_++);
    ShiftInfo stored = shift;
    stored.id = id;
    shifts_[id] = stored;

    logger_.info("Created shift: id={}, name={}, analysts={}", id, shift.name, shift.analysts.size());
    return id;
}

std::vector<ShiftInfo> SOCManager::getShifts() {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ShiftInfo> result;
    result.reserve(shifts_.size());
    for (const auto& [id, shift] : shifts_) {
        result.push_back(shift);
    }
    return result;
}

std::string SOCManager::addHandoffNote(const HandoffNote& note) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = "HN-" + std::to_string(nextHandoffId_++);
    HandoffNote stored = note;
    stored.id = id;
    handoffNotes_[note.shiftId].push_back(stored);

    logger_.info("Added handoff note {} for shift {}: from={}, to={}",
                 id, note.shiftId, note.fromAnalyst, note.toAnalyst);
    return id;
}

std::vector<HandoffNote> SOCManager::getHandoffNotes(const std::string& shiftId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = handoffNotes_.find(shiftId);
    if (it != handoffNotes_.end()) {
        return it->second;
    }
    return {};
}

std::string SOCManager::createTicket(const TicketInfo& ticket) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = "TKT-" + std::to_string(nextTicketId_++);
    TicketInfo stored = ticket;
    stored.id = id;
    tickets_[id] = stored;

    logger_.info("Created ticket: id={}, system={}, title={}", id, ticket.system, ticket.title);
    return id;
}

bool SOCManager::syncTicket(const std::string& ticketId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = tickets_.find(ticketId);
    if (it == tickets_.end()) {
        logger_.warn("syncTicket failed: ticket {} not found", ticketId);
        return false;
    }

    // Simulate sync by updating the lastSyncAt field
    it->second.lastSyncAt = "synced";
    it->second.status = "synced";
    logger_.info("Synced ticket {} with {}", ticketId, it->second.system);
    return true;
}

std::vector<TicketInfo> SOCManager::getTickets(const std::string& caseId) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<TicketInfo> result;
    for (const auto& [id, ticket] : tickets_) {
        if (ticket.caseId == caseId) {
            result.push_back(ticket);
        }
    }
    return result;
}

} // namespace ThreatOne::SOC
