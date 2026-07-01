#include "ai/AutoInvestigation.h"

#include <algorithm>
#include <sstream>
#include <set>

namespace ThreatOne::AI {

AutoInvestigation::AutoInvestigation()
    : logger_(Core::Logger::instance().getModuleLogger("AutoInvestigation")) {
    logger_.info("AutoInvestigation initialized");
}

InvestigationResult AutoInvestigation::investigate(
    const std::string& triggerId,
    const std::map<std::string, std::string>& triggerData) const {

    logger_.info("Starting investigation for trigger: {}", triggerId);

    InvestigationResult result;
    result.incidentId = triggerId;

    // Step 1: Gather evidence
    auto evidence = gatherEvidence(triggerId, triggerData);
    logger_.debug("Gathered {} pieces of evidence", evidence.size());

    // Step 2: Correlate events
    auto correlations = correlateEvents(evidence);
    logger_.debug("Found {} correlations", correlations.size());

    // Step 3: Determine scope
    result.affectedAssets = determineScope(correlations);
    result.scope = std::to_string(result.affectedAssets.size()) + " assets affected";

    // Step 4: Build timeline
    result.timeline = buildTimeline(evidence);

    // Step 5: Identify root cause
    result.rootCause = identifyRootCause(evidence, correlations);

    // Step 6: Calculate confidence
    result.confidence = calculateConfidence(evidence, correlations);

    // Step 7: Suggest remediation
    result.suggestedRemediation = suggestRemediation(result);

    logger_.info("Investigation complete for {}: scope={}, confidence={:.2f}",
                 triggerId, result.scope, result.confidence);

    return result;
}

std::vector<Evidence> AutoInvestigation::gatherEvidence(
    const std::string& triggerId,
    const std::map<std::string, std::string>& triggerData) const {

    std::vector<Evidence> evidence;

    // Create primary evidence from trigger data
    Evidence primary;
    primary.type = "trigger";
    primary.source = triggerId;
    primary.relevance = 1.0;

    // Extract data from trigger fields
    auto it = triggerData.find("timestamp");
    if (it != triggerData.end()) {
        primary.timestamp = it->second;
    }

    std::string dataStr;
    for (const auto& [key, value] : triggerData) {
        if (!dataStr.empty()) dataStr += "; ";
        dataStr += key + "=" + value;
    }
    primary.data = dataStr;
    evidence.push_back(primary);

    // Extract related IPs as network evidence
    it = triggerData.find("source_ip");
    if (it != triggerData.end()) {
        Evidence netEvidence;
        netEvidence.type = "network";
        netEvidence.source = "network_log";
        netEvidence.data = "Source IP: " + it->second;
        netEvidence.timestamp = primary.timestamp;
        netEvidence.relevance = 0.9;
        evidence.push_back(netEvidence);
    }

    it = triggerData.find("destination_ip");
    if (it != triggerData.end()) {
        Evidence netEvidence;
        netEvidence.type = "network";
        netEvidence.source = "network_log";
        netEvidence.data = "Destination IP: " + it->second;
        netEvidence.timestamp = primary.timestamp;
        netEvidence.relevance = 0.8;
        evidence.push_back(netEvidence);
    }

    // Extract file-related evidence
    it = triggerData.find("file_path");
    if (it != triggerData.end()) {
        Evidence fileEvidence;
        fileEvidence.type = "file";
        fileEvidence.source = "file_system";
        fileEvidence.data = "File: " + it->second;
        fileEvidence.timestamp = primary.timestamp;
        fileEvidence.relevance = 0.85;
        evidence.push_back(fileEvidence);
    }

    // Extract process-related evidence
    it = triggerData.find("process_name");
    if (it != triggerData.end()) {
        Evidence procEvidence;
        procEvidence.type = "process";
        procEvidence.source = "process_monitor";
        procEvidence.data = "Process: " + it->second;
        procEvidence.timestamp = primary.timestamp;
        procEvidence.relevance = 0.85;
        evidence.push_back(procEvidence);
    }

    // Extract user-related evidence
    it = triggerData.find("user");
    if (it != triggerData.end()) {
        Evidence userEvidence;
        userEvidence.type = "user_activity";
        userEvidence.source = "auth_log";
        userEvidence.data = "User: " + it->second;
        userEvidence.timestamp = primary.timestamp;
        userEvidence.relevance = 0.75;
        evidence.push_back(userEvidence);
    }

    // Extract threat type as classification evidence
    it = triggerData.find("threat_type");
    if (it != triggerData.end()) {
        Evidence classEvidence;
        classEvidence.type = "classification";
        classEvidence.source = "threat_classifier";
        classEvidence.data = "Threat type: " + it->second;
        classEvidence.timestamp = primary.timestamp;
        classEvidence.relevance = 0.95;
        evidence.push_back(classEvidence);
    }

    return evidence;
}

std::vector<std::string> AutoInvestigation::correlateEvents(
    const std::vector<Evidence>& evidence) const {

    std::vector<std::string> correlations;

    // Correlate by common source
    std::map<std::string, std::vector<size_t>> sourceGroups;
    for (size_t i = 0; i < evidence.size(); ++i) {
        sourceGroups[evidence[i].source].push_back(i);
    }

    for (const auto& [source, indices] : sourceGroups) {
        if (indices.size() > 1) {
            correlations.push_back("Multiple events from source: " + source);
        }
    }

    // Correlate by type
    std::map<std::string, int> typeCounts;
    for (const auto& ev : evidence) {
        typeCounts[ev.type]++;
    }

    for (const auto& [type, count] : typeCounts) {
        if (count > 1) {
            correlations.push_back("Correlated " + std::to_string(count) +
                                   " events of type: " + type);
        }
    }

    // Correlate network evidence with process evidence
    bool hasNetwork = false;
    bool hasProcess = false;
    bool hasFile = false;
    for (const auto& ev : evidence) {
        if (ev.type == "network") hasNetwork = true;
        if (ev.type == "process") hasProcess = true;
        if (ev.type == "file") hasFile = true;
    }

    if (hasNetwork && hasProcess) {
        correlations.push_back("Network activity correlated with process execution");
    }
    if (hasFile && hasProcess) {
        correlations.push_back("File system changes correlated with process activity");
    }
    if (hasNetwork && hasFile) {
        correlations.push_back("Network activity correlated with file system changes");
    }

    // If no correlations found, add basic observation
    if (correlations.empty()) {
        correlations.push_back("Single isolated event detected");
    }

    return correlations;
}

std::vector<std::string> AutoInvestigation::determineScope(
    const std::vector<std::string>& correlations) const {

    std::set<std::string> assets;

    // Extract asset references from correlations
    for (const auto& correlation : correlations) {
        // Any correlation implies at least one asset
        if (correlation.find("network") != std::string::npos) {
            assets.insert("network_segment");
        }
        if (correlation.find("process") != std::string::npos) {
            assets.insert("endpoint_host");
        }
        if (correlation.find("file") != std::string::npos) {
            assets.insert("file_system");
        }
        if (correlation.find("source") != std::string::npos) {
            assets.insert("affected_system");
        }
    }

    // Ensure at least one asset is identified
    if (assets.empty()) {
        assets.insert("primary_target");
    }

    return std::vector<std::string>(assets.begin(), assets.end());
}

std::vector<std::string> AutoInvestigation::suggestRemediation(
    const InvestigationResult& result) const {

    std::vector<std::string> remediation;

    // Remediation based on root cause
    if (result.rootCause.find("network") != std::string::npos ||
        result.rootCause.find("IP") != std::string::npos) {
        remediation.push_back("Block malicious IP addresses at firewall");
        remediation.push_back("Review network access control lists");
    }

    if (result.rootCause.find("file") != std::string::npos ||
        result.rootCause.find("malware") != std::string::npos) {
        remediation.push_back("Quarantine malicious files");
        remediation.push_back("Run full antimalware scan on affected systems");
    }

    if (result.rootCause.find("process") != std::string::npos ||
        result.rootCause.find("execution") != std::string::npos) {
        remediation.push_back("Terminate malicious processes");
        remediation.push_back("Review process execution policies");
    }

    if (result.rootCause.find("credential") != std::string::npos ||
        result.rootCause.find("auth") != std::string::npos ||
        result.rootCause.find("user") != std::string::npos) {
        remediation.push_back("Reset compromised credentials");
        remediation.push_back("Enable multi-factor authentication");
    }

    // Scope-based remediation
    if (result.affectedAssets.size() > 2) {
        remediation.push_back("Isolate affected network segment");
        remediation.push_back("Activate incident response team");
    }

    // General remediation if nothing specific
    if (remediation.empty()) {
        remediation.push_back("Increase monitoring on affected systems");
        remediation.push_back("Review security event logs for additional indicators");
        remediation.push_back("Update detection signatures");
    }

    return remediation;
}

std::string AutoInvestigation::identifyRootCause(
    const std::vector<Evidence>& evidence,
    const std::vector<std::string>& correlations) const {

    if (evidence.empty()) {
        return "Unable to determine root cause - insufficient evidence";
    }

    // Find the highest-relevance evidence as primary indicator
    const Evidence* primary = &evidence[0];
    for (const auto& ev : evidence) {
        if (ev.relevance > primary->relevance) {
            primary = &ev;
        }
    }

    // Build root cause description
    std::string rootCause;

    // Check for classification evidence first
    for (const auto& ev : evidence) {
        if (ev.type == "classification") {
            rootCause = ev.data;
            break;
        }
    }

    if (rootCause.empty()) {
        rootCause = "Initial " + primary->type + " event from " + primary->source;
    }

    // Add correlation context
    if (correlations.size() > 1) {
        rootCause += " with " + std::to_string(correlations.size()) + " correlated indicators";
    }

    return rootCause;
}

std::vector<std::string> AutoInvestigation::buildTimeline(
    const std::vector<Evidence>& evidence) const {

    std::vector<std::string> timeline;

    // Sort evidence by timestamp (lexicographic for ISO format strings)
    std::vector<const Evidence*> sorted;
    sorted.reserve(evidence.size());
    for (const auto& ev : evidence) {
        sorted.push_back(&ev);
    }

    std::sort(sorted.begin(), sorted.end(),
              [](const Evidence* a, const Evidence* b) {
                  return a->timestamp < b->timestamp;
              });

    for (const auto* ev : sorted) {
        std::string entry;
        if (!ev->timestamp.empty()) {
            entry = "[" + ev->timestamp + "] ";
        }
        entry += ev->type + ": " + ev->data;
        timeline.push_back(entry);
    }

    return timeline;
}

double AutoInvestigation::calculateConfidence(
    const std::vector<Evidence>& evidence,
    const std::vector<std::string>& correlations) const {

    if (evidence.empty()) return 0.0;

    // Base confidence from evidence quantity
    double evidenceScore = std::min(1.0, static_cast<double>(evidence.size()) / 5.0);

    // Boost from correlations
    double correlationScore = std::min(1.0, static_cast<double>(correlations.size()) / 3.0);

    // Average relevance of evidence
    double avgRelevance = 0.0;
    for (const auto& ev : evidence) {
        avgRelevance += ev.relevance;
    }
    avgRelevance /= static_cast<double>(evidence.size());

    // Combined confidence (weighted average)
    double confidence = 0.4 * evidenceScore + 0.3 * correlationScore + 0.3 * avgRelevance;

    return std::min(1.0, std::max(0.0, confidence));
}

} // namespace ThreatOne::AI
