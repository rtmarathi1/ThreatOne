#include "xdr/AutomatedInvestigation.h"

#include <algorithm>

namespace ThreatOne::XDR {

AutomatedInvestigation::AutomatedInvestigation()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("AutomatedInvestigation")) {
    logger_.info("AutomatedInvestigation initialized");

    // Register default playbooks
    InvestigationPlaybook defaultPlaybook;
    defaultPlaybook.id = generatePlaybookId();
    defaultPlaybook.name = "default";
    defaultPlaybook.description = "Default investigation playbook";
    defaultPlaybook.triggerCondition = "any";
    defaultPlaybook.steps = {
        {"Gather Context", "gather_context", "pending", ""},
        {"Check Reputation", "check_reputation", "pending", ""},
        {"Correlate Events", "correlate_events", "pending", ""},
        {"Determine Scope", "determine_scope", "pending", ""}
    };
    playbooks_[defaultPlaybook.name] = defaultPlaybook;

    InvestigationPlaybook malwarePlaybook;
    malwarePlaybook.id = generatePlaybookId();
    malwarePlaybook.name = "malware_response";
    malwarePlaybook.description = "Malware incident response playbook";
    malwarePlaybook.triggerCondition = "high_severity";
    malwarePlaybook.steps = {
        {"Gather Context", "gather_context", "pending", ""},
        {"Enrich IOC", "enrich_ioc", "pending", ""},
        {"Check Reputation", "check_reputation", "pending", ""},
        {"Correlate Events", "correlate_events", "pending", ""},
        {"Determine Scope", "determine_scope", "pending", ""}
    };
    playbooks_[malwarePlaybook.name] = malwarePlaybook;
}

std::string AutomatedInvestigation::generateInvestigationId() {
    return "INV-" + std::to_string(nextInvestigationId_++);
}

std::string AutomatedInvestigation::generatePlaybookId() {
    return "PB-" + std::to_string(nextPlaybookId_++);
}

std::string AutomatedInvestigation::registerPlaybook(const InvestigationPlaybook& playbook) {
    std::lock_guard<std::mutex> lock(mutex_);
    InvestigationPlaybook stored = playbook;
    if (stored.id.empty()) {
        stored.id = generatePlaybookId();
    }
    playbooks_[stored.name] = stored;
    logger_.info("Registered playbook: name={}", stored.name);
    return stored.id;
}

std::vector<InvestigationPlaybook> AutomatedInvestigation::getPlaybooks() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<InvestigationPlaybook> result;
    result.reserve(playbooks_.size());
    for (const auto& [name, pb] : playbooks_) {
        result.push_back(pb);
    }
    return result;
}

InvestigationPlaybook AutomatedInvestigation::getPlaybook(const std::string& playbookId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [name, pb] : playbooks_) {
        if (pb.id == playbookId || pb.name == playbookId) {
            return pb;
        }
    }
    return InvestigationPlaybook{};
}

void AutomatedInvestigation::executePlaybookSteps(InvestigationResult& result,
                                                   const Correlation& correlation,
                                                   const std::map<std::string, EndpointEvent>& events) {
    auto pbIt = playbooks_.find(result.playbook);
    if (pbIt == playbooks_.end()) {
        // Use default if specified playbook not found
        pbIt = playbooks_.find("default");
        if (pbIt == playbooks_.end()) return;
    }

    const auto& playbook = pbIt->second;

    for (auto step : playbook.steps) {
        step.status = "completed";

        if (step.action == "gather_context") {
            result.findings.push_back("Correlation involves " +
                                       std::to_string(correlation.eventIds.size()) + " events");
            result.findings.push_back("Severity: " + correlation.severity);
            result.findings.push_back("Confidence: " + std::to_string(correlation.confidence));
            step.result = "Context gathered";
        } else if (step.action == "enrich_ioc") {
            for (const auto& eventId : correlation.eventIds) {
                auto evtIt = events.find(eventId);
                if (evtIt != events.end()) {
                    result.evidence.push_back("Event " + eventId + " on endpoint " +
                                              evtIt->second.endpointId + ": " +
                                              evtIt->second.eventType);
                } else {
                    result.evidence.push_back("Alert reference: " + eventId);
                }
            }
            step.result = "IOC enrichment complete";
        } else if (step.action == "check_reputation") {
            // Simulate reputation check
            step.result = "Reputation check complete";
        } else if (step.action == "correlate_events") {
            // Compute risk score based on correlation data
            result.riskScore = correlation.confidence * 100.0;
            if (correlation.severity == "critical") result.riskScore = std::min(100.0, result.riskScore + 30);
            else if (correlation.severity == "high") result.riskScore = std::min(100.0, result.riskScore + 20);
            step.result = "Events correlated, risk score: " + std::to_string(result.riskScore);
        } else if (step.action == "determine_scope") {
            if (correlation.confidence >= 0.7) {
                result.findings.push_back("High confidence - automated response recommended");
                result.recommendedAction = "isolate_endpoint";
            }
            step.result = "Scope determined";
        }

        result.executedSteps.push_back(step);
    }
}

std::string AutomatedInvestigation::startInvestigation(const std::string& correlationId,
                                                        const std::string& playbook,
                                                        const Correlation& correlation,
                                                        const std::map<std::string, EndpointEvent>& events) {
    std::lock_guard<std::mutex> lock(mutex_);

    InvestigationResult result;
    result.investigationId = generateInvestigationId();
    result.correlationId = correlationId;
    result.status = InvestigationStatus::InProgress;
    result.playbook = playbook;

    // Execute playbook steps
    executePlaybookSteps(result, correlation, events);

    investigations_[result.investigationId] = result;
    logger_.info("Started investigation: id={}, correlation={}, playbook={}",
                 result.investigationId, correlationId, playbook);
    return result.investigationId;
}

InvestigationResult AutomatedInvestigation::getInvestigationResult(const std::string& investigationId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = investigations_.find(investigationId);
    if (it != investigations_.end()) {
        return it->second;
    }
    return InvestigationResult{};
}

std::vector<InvestigationResult> AutomatedInvestigation::getActiveInvestigations() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<InvestigationResult> result;
    for (const auto& [id, inv] : investigations_) {
        if (inv.status == InvestigationStatus::InProgress) {
            result.push_back(inv);
        }
    }
    return result;
}

std::vector<InvestigationResult> AutomatedInvestigation::getAllInvestigations() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<InvestigationResult> result;
    result.reserve(investigations_.size());
    for (const auto& [id, inv] : investigations_) {
        result.push_back(inv);
    }
    return result;
}

size_t AutomatedInvestigation::getInvestigationCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return investigations_.size();
}

size_t AutomatedInvestigation::getActiveCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& [id, inv] : investigations_) {
        if (inv.status == InvestigationStatus::InProgress) {
            count++;
        }
    }
    return count;
}

} // namespace ThreatOne::XDR
