#include "soc/WorkflowAutomation.h"

namespace ThreatOne::SOC {

WorkflowAutomation::WorkflowAutomation()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("WorkflowAutomation")) {
    logger_.info("WorkflowAutomation initialized");
}

std::string WorkflowAutomation::createWorkflow(const WorkflowDefinition& workflow) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = "WF-" + std::to_string(nextWorkflowId_++);
    WorkflowDefinition stored = workflow;
    stored.id = id;
    workflows_[id] = stored;

    logger_.info("Created workflow: id={}, name={}", id, workflow.name);
    return id;
}

bool WorkflowAutomation::deleteWorkflow(const std::string& workflowId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = workflows_.find(workflowId);
    if (it == workflows_.end()) {
        return false;
    }

    workflows_.erase(it);
    logger_.info("Deleted workflow: id={}", workflowId);
    return true;
}

bool WorkflowAutomation::enableWorkflow(const std::string& workflowId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = workflows_.find(workflowId);
    if (it == workflows_.end()) {
        return false;
    }

    it->second.enabled = true;
    logger_.info("Enabled workflow: id={}", workflowId);
    return true;
}

bool WorkflowAutomation::disableWorkflow(const std::string& workflowId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = workflows_.find(workflowId);
    if (it == workflows_.end()) {
        return false;
    }

    it->second.enabled = false;
    logger_.info("Disabled workflow: id={}", workflowId);
    return true;
}

std::vector<WorkflowDefinition> WorkflowAutomation::getWorkflows() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<WorkflowDefinition> result;
    result.reserve(workflows_.size());
    for (const auto& [id, wf] : workflows_) {
        result.push_back(wf);
    }
    return result;
}

WorkflowDefinition WorkflowAutomation::getWorkflow(const std::string& workflowId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = workflows_.find(workflowId);
    if (it != workflows_.end()) {
        return it->second;
    }
    return {};
}

bool WorkflowAutomation::workflowExists(const std::string& workflowId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return workflows_.find(workflowId) != workflows_.end();
}

WorkflowInfo WorkflowAutomation::getWorkflowForCase(const std::string& caseId, CaseStatus status) const {
    // Returns the standard investigation workflow mapped to current case status
    WorkflowInfo workflow;
    workflow.id = "WF-" + caseId;
    workflow.name = "Standard Investigation";
    workflow.steps = {"Triage", "Investigate", "Contain", "Remediate", "Close"};

    switch (status) {
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

bool WorkflowAutomation::evaluateTriggers(TriggerType type, const std::string& context) {
    std::lock_guard<std::mutex> lock(mutex_);

    bool triggered = false;
    for (const auto& [id, wf] : workflows_) {
        if (!wf.enabled) continue;

        for (const auto& trigger : wf.triggers) {
            if (trigger.type == type) {
                // Trigger matched - in production would execute actions
                logger_.info("Workflow {} triggered by type={}, context={}",
                             wf.name, static_cast<int>(type), context);
                triggered = true;
            }
        }
    }
    return triggered;
}

size_t WorkflowAutomation::getWorkflowCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return workflows_.size();
}

size_t WorkflowAutomation::getActiveWorkflowCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& [id, wf] : workflows_) {
        if (wf.enabled) {
            count++;
        }
    }
    return count;
}

} // namespace ThreatOne::SOC
