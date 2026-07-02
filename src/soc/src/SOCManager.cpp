#include "soc/SOCManager.h"
#include "core/ServiceLocator.h"

#include <algorithm>
#include <mutex>
#include <string>
#include <vector>

namespace ThreatOne::SOC {

SOCManager::SOCManager()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("SOCManager")) {
    // Initialize sub-components
    caseManager_ = std::make_shared<CaseManager>();
    incidentManager_ = std::make_shared<IncidentManager>();
    playbookEngine_ = std::make_shared<PlaybookEngine>();
    workflowAutomation_ = std::make_shared<WorkflowAutomation>();
    evidenceCollector_ = std::make_shared<EvidenceCollector>();
    timelineBuilder_ = std::make_shared<TimelineBuilder>();
    dashboardData_ = std::make_shared<SOCDashboardData>();
    alertTriage_ = std::make_shared<AlertTriage>();

    // Register key sub-components with ServiceLocator for cross-module access
    auto& locator = Core::ServiceLocator::instance();
    locator.registerService<CaseManager>(caseManager_);
    locator.registerService<IncidentManager>(incidentManager_);
    locator.registerService<PlaybookEngine>(playbookEngine_);

    logger_.info("SOCManager initialized with all sub-components");
}

std::string SOCManager::createCase(const CaseInfo& caseInfo) {
    return caseManager_->createCase(caseInfo);
}

bool SOCManager::assignCase(const std::string& caseId, const std::string& analystId) {
    return caseManager_->assignCase(caseId, analystId);
}

bool SOCManager::escalate(const std::string& caseId, const std::string& reason) {
    return caseManager_->escalate(caseId, reason);
}

bool SOCManager::updateCaseStatus(const std::string& caseId, CaseStatus status) {
    return caseManager_->updateCaseStatus(caseId, status);
}

WorkflowInfo SOCManager::getWorkflow(const std::string& caseId) {
    if (!caseManager_->caseExists(caseId)) {
        return {};
    }
    auto caseInfo = caseManager_->getCase(caseId);
    return workflowAutomation_->getWorkflowForCase(caseId, caseInfo.status);
}

SOCMetrics SOCManager::getMetrics() {
    auto cases = caseManager_->getAllCases();
    auto analysts = caseManager_->getActiveAnalysts();
    return dashboardData_->computeMetrics(cases, analysts);
}

std::string SOCManager::addEvidence(const std::string& caseId, const EvidenceItem& evidence) {
    if (!caseManager_->caseExists(caseId)) {
        logger_.warn("addEvidence failed: case {} not found", caseId);
        return "";
    }
    return evidenceCollector_->addEvidence(caseId, evidence);
}

std::vector<EvidenceItem> SOCManager::getEvidence(const std::string& caseId) {
    return evidenceCollector_->getEvidence(caseId);
}

std::string SOCManager::createPlaybook(const Playbook& playbook) {
    return playbookEngine_->createPlaybook(playbook);
}

std::vector<Playbook> SOCManager::getPlaybooks() {
    return playbookEngine_->getPlaybooks();
}

std::string SOCManager::executePlaybook(const std::string& playbookId, const std::string& caseId) {
    if (!playbookEngine_->playbookExists(playbookId)) {
        logger_.warn("executePlaybook failed: playbook {} not found", playbookId);
        return "";
    }
    if (!caseManager_->caseExists(caseId)) {
        logger_.warn("executePlaybook failed: case {} not found", caseId);
        return "";
    }
    return playbookEngine_->executePlaybook(playbookId, caseId);
}

PlaybookExecution SOCManager::getPlaybookExecution(const std::string& executionId) {
    return playbookEngine_->getPlaybookExecution(executionId);
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
