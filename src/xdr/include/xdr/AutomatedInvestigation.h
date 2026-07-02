#pragma once

#include "xdr/IXDREngine.h"
#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>
#include <functional>

namespace ThreatOne::XDR {

// Represents a playbook step
struct PlaybookStep {
    std::string name;
    std::string action;   // "gather_context", "enrich_ioc", "check_reputation", "correlate_events", "determine_scope"
    std::string status;   // "pending", "running", "completed", "failed"
    std::string result;
};

// Represents an investigation playbook
struct InvestigationPlaybook {
    std::string id;
    std::string name;
    std::string description;
    std::vector<PlaybookStep> steps;
    std::string triggerCondition;  // "high_severity", "multi_stage", "cross_source"
};

// Extended investigation result with playbook execution
struct InvestigationResult {
    std::string investigationId;
    std::string correlationId;
    InvestigationStatus status = InvestigationStatus::InProgress;
    std::string playbook;
    std::vector<std::string> findings;
    std::vector<std::string> evidence;
    std::vector<PlaybookStep> executedSteps;
    double riskScore = 0.0;
    std::string recommendedAction;
};

class AutomatedInvestigation {
public:
    AutomatedInvestigation();
    ~AutomatedInvestigation() = default;

    // Playbook management
    std::string registerPlaybook(const InvestigationPlaybook& playbook);
    [[nodiscard]] std::vector<InvestigationPlaybook> getPlaybooks() const;
    [[nodiscard]] InvestigationPlaybook getPlaybook(const std::string& playbookId) const;

    // Investigation execution
    std::string startInvestigation(const std::string& correlationId, const std::string& playbook,
                                   const Correlation& correlation,
                                   const std::map<std::string, EndpointEvent>& events);
    [[nodiscard]] InvestigationResult getInvestigationResult(const std::string& investigationId) const;

    // Investigation query
    [[nodiscard]] std::vector<InvestigationResult> getActiveInvestigations() const;
    [[nodiscard]] std::vector<InvestigationResult> getAllInvestigations() const;

    // Stats
    [[nodiscard]] size_t getInvestigationCount() const;
    [[nodiscard]] size_t getActiveCount() const;

private:
    std::string generateInvestigationId();
    std::string generatePlaybookId();
    void executePlaybookSteps(InvestigationResult& result, const Correlation& correlation,
                              const std::map<std::string, EndpointEvent>& events);

    mutable std::mutex mutex_;
    std::map<std::string, InvestigationPlaybook> playbooks_;
    std::map<std::string, InvestigationResult> investigations_;
    int nextInvestigationId_ = 1;
    int nextPlaybookId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::XDR
