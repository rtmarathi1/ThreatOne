#include "soc/PlaybookEngine.h"
#include <mutex>

namespace ThreatOne::SOC {

PlaybookEngine::PlaybookEngine()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("PlaybookEngine")) {
    logger_.info("PlaybookEngine initialized");
}

std::string PlaybookEngine::createPlaybook(const Playbook& playbook) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = "PB-" + std::to_string(nextPlaybookId_++);
    Playbook stored = playbook;
    stored.id = id;
    playbooks_[id] = stored;

    logger_.info("Created playbook: id={}, name={}, steps={}", id, playbook.name, playbook.steps.size());
    return id;
}

bool PlaybookEngine::deletePlaybook(const std::string& playbookId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = playbooks_.find(playbookId);
    if (it == playbooks_.end()) {
        return false;
    }

    playbooks_.erase(it);
    logger_.info("Deleted playbook: id={}", playbookId);
    return true;
}

std::vector<Playbook> PlaybookEngine::getPlaybooks() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<Playbook> result;
    result.reserve(playbooks_.size());
    for (const auto& [id, pb] : playbooks_) {
        result.push_back(pb);
    }
    return result;
}

Playbook PlaybookEngine::getPlaybook(const std::string& playbookId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = playbooks_.find(playbookId);
    if (it != playbooks_.end()) {
        return it->second;
    }
    return {};
}

bool PlaybookEngine::playbookExists(const std::string& playbookId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return playbooks_.find(playbookId) != playbooks_.end();
}

std::string PlaybookEngine::executePlaybook(const std::string& playbookId, const std::string& caseId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto pbIt = playbooks_.find(playbookId);
    if (pbIt == playbooks_.end()) {
        logger_.warn("executePlaybook failed: playbook {} not found", playbookId);
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
        if (!step.condition.empty() && !evaluateCondition(step.condition)) {
            execution.results.push_back("Step " + step.name + ": skipped (condition not met)");
            continue;
        }

        // Execute the step
        execution.results.push_back(executeStep(step));
        execution.currentStepIndex = i + 1;
    }

    // Mark execution as completed
    execution.status = ExecutionStatus::Completed;
    execution.completedAt = "now";
    executions_[execId] = execution;

    logger_.info("Executed playbook {} on case {}: execution={}", playbookId, caseId, execId);
    return execId;
}

PlaybookExecution PlaybookEngine::getPlaybookExecution(const std::string& executionId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = executions_.find(executionId);
    if (it != executions_.end()) {
        return it->second;
    }
    return {};
}

std::vector<PlaybookExecution> PlaybookEngine::getExecutionsForCase(const std::string& caseId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<PlaybookExecution> result;
    for (const auto& [id, exec] : executions_) {
        if (exec.caseId == caseId) {
            result.push_back(exec);
        }
    }
    return result;
}

bool PlaybookEngine::validatePlaybook(const Playbook& playbook) const {
    // A valid playbook must have a name and at least conceptually valid structure
    if (playbook.name.empty()) {
        return false;
    }
    // Steps should have names and action types
    for (const auto& step : playbook.steps) {
        if (step.name.empty()) {
            return false;
        }
    }
    return true;
}

std::string PlaybookEngine::executeStep(const PlaybookStep& step) {
    // Execute a single step and return result description
    return "Step " + step.name + ": completed (" + step.actionType + ")";
}

bool PlaybookEngine::evaluateCondition(const std::string& condition) const {
    // Simple condition evaluation: "skip" means do not run
    if (condition == "skip") {
        return false;
    }
    return true;
}

} // namespace ThreatOne::SOC
