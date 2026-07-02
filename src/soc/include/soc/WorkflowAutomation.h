#pragma once

#include "soc/ISOCManager.h"
#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>
#include <functional>

namespace ThreatOne::SOC {

enum class TriggerType {
    CaseCreated,
    CaseStatusChanged,
    SeverityEscalation,
    TimeElapsed,
    ManualTrigger
};

struct WorkflowTrigger {
    std::string id;
    TriggerType type = TriggerType::ManualTrigger;
    std::string condition;
};

struct WorkflowAction {
    std::string id;
    std::string name;
    std::string actionType;  // "notify", "assign", "escalate", "execute_playbook"
    std::unordered_map<std::string, std::string> parameters;
};

struct WorkflowDefinition {
    std::string id;
    std::string name;
    std::string description;
    bool enabled = true;
    std::vector<WorkflowTrigger> triggers;
    std::vector<WorkflowAction> actions;
};

class WorkflowAutomation {
public:
    WorkflowAutomation();
    ~WorkflowAutomation() = default;

    // Workflow management
    std::string createWorkflow(const WorkflowDefinition& workflow);
    bool deleteWorkflow(const std::string& workflowId);
    bool enableWorkflow(const std::string& workflowId);
    bool disableWorkflow(const std::string& workflowId);

    // Queries
    [[nodiscard]] std::vector<WorkflowDefinition> getWorkflows() const;
    [[nodiscard]] WorkflowDefinition getWorkflow(const std::string& workflowId) const;
    [[nodiscard]] bool workflowExists(const std::string& workflowId) const;

    // Workflow for case status mapping (used by SOCManager)
    [[nodiscard]] WorkflowInfo getWorkflowForCase(const std::string& caseId, CaseStatus status) const;

    // Trigger evaluation
    bool evaluateTriggers(TriggerType type, const std::string& context);

    // Statistics
    [[nodiscard]] size_t getWorkflowCount() const;
    [[nodiscard]] size_t getActiveWorkflowCount() const;

private:
    mutable std::mutex mutex_;
    std::map<std::string, WorkflowDefinition> workflows_;
    int nextWorkflowId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::SOC
