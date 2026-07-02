#pragma once

#include "soc/ISOCManager.h"
#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>

namespace ThreatOne::SOC {

class PlaybookEngine {
public:
    PlaybookEngine();
    ~PlaybookEngine() = default;

    // Playbook management
    std::string createPlaybook(const Playbook& playbook);
    bool deletePlaybook(const std::string& playbookId);
    [[nodiscard]] std::vector<Playbook> getPlaybooks() const;
    [[nodiscard]] Playbook getPlaybook(const std::string& playbookId) const;
    [[nodiscard]] bool playbookExists(const std::string& playbookId) const;

    // Playbook execution
    std::string executePlaybook(const std::string& playbookId, const std::string& caseId);
    [[nodiscard]] PlaybookExecution getPlaybookExecution(const std::string& executionId) const;
    [[nodiscard]] std::vector<PlaybookExecution> getExecutionsForCase(const std::string& caseId) const;

    // Validation
    [[nodiscard]] bool validatePlaybook(const Playbook& playbook) const;

private:
    std::string executeStep(const PlaybookStep& step);
    bool evaluateCondition(const std::string& condition) const;

    mutable std::mutex mutex_;
    std::map<std::string, Playbook> playbooks_;
    std::map<std::string, PlaybookExecution> executions_;
    int nextPlaybookId_ = 1;
    int nextExecutionId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::SOC
