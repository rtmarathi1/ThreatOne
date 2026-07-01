#include "compliance/ComplianceScanner.h"

#include <algorithm>
#include <chrono>
#include <sstream>

namespace ThreatOne::Compliance {

ComplianceScanner::ComplianceScanner(ComplianceFramework& framework)
    : framework_(framework)
    , logger_("ComplianceScanner") {
    logger_.info("ComplianceScanner initialized");
}

std::string ComplianceScanner::generateFindingId() {
    std::ostringstream oss;
    oss << "finding-" << nextFindingId_.fetch_add(1);
    return oss.str();
}

std::string ComplianceScanner::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::ctime(&time);
    std::string result = oss.str();
    if (!result.empty() && result.back() == '\n') {
        result.pop_back();
    }
    return result;
}

FindingStatus ComplianceScanner::evaluateControl(
    const ControlInfo& control, const SystemState& state) const {
    // Check if control is configured as not applicable
    auto naIt = state.configurations.find(control.id + ".not_applicable");
    if (naIt != state.configurations.end() && naIt->second == "true") {
        return FindingStatus::NotApplicable;
    }

    // Check if control has a specific pass/fail config
    auto statusIt = state.configurations.find(control.id + ".status");
    if (statusIt != state.configurations.end()) {
        if (statusIt->second == "pass") return FindingStatus::Pass;
        if (statusIt->second == "fail") return FindingStatus::Fail;
        if (statusIt->second == "warning") return FindingStatus::Warning;
    }

    // Check if any required features are enabled
    bool hasFeature = false;
    for (const auto& feature : state.enabledFeatures) {
        if (feature == control.categoryId || feature == control.id) {
            hasFeature = true;
            break;
        }
    }

    // Check if policy is installed
    bool hasPolicy = false;
    for (const auto& policy : state.installedPolicies) {
        if (policy == control.categoryId || policy == control.id) {
            hasPolicy = true;
            break;
        }
    }

    if (hasFeature && hasPolicy) return FindingStatus::Pass;
    if (hasFeature || hasPolicy) return FindingStatus::Warning;
    if (control.implemented) return FindingStatus::Warning;
    return FindingStatus::Fail;
}

FindingSeverity ComplianceScanner::determineSeverity(const ControlInfo& control) const {
    // Determine severity based on control properties
    if (control.categoryId.find("SEC") != std::string::npos ||
        control.categoryId.find("TEC") != std::string::npos ||
        control.categoryId.find("R1") != std::string::npos) {
        return FindingSeverity::Critical;
    }
    if (control.categoryId.find("PR") != std::string::npos ||
        control.categoryId.find("A9") != std::string::npos ||
        control.categoryId.find("R3") != std::string::npos) {
        return FindingSeverity::High;
    }
    if (control.categoryId.find("DE") != std::string::npos ||
        control.categoryId.find("CC") != std::string::npos) {
        return FindingSeverity::Medium;
    }
    return FindingSeverity::Low;
}

ComplianceFinding ComplianceScanner::scanControl(
    const ControlInfo& control, const SystemState& state) {
    ComplianceFinding finding;
    finding.id = generateFindingId();
    finding.controlId = control.id;
    finding.framework = control.framework;
    finding.status = evaluateControl(control, state);
    finding.severity = determineSeverity(control);
    finding.description = "Assessment of " + control.name;
    finding.timestamp = getCurrentTimestamp();

    if (finding.status == FindingStatus::Pass) {
        finding.description += " - meets requirements";
    } else if (finding.status == FindingStatus::Fail) {
        finding.description += " - does not meet requirements";
    } else if (finding.status == FindingStatus::Warning) {
        finding.description += " - partially meets requirements";
    } else {
        finding.description += " - not applicable to this environment";
    }

    return finding;
}

ThreatOne::Core::Result<std::vector<ComplianceFinding>> ComplianceScanner::scan(
    Framework framework, const SystemState& state) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto controls = framework_.getControls(framework);
    if (controls.empty()) {
        return ThreatOne::Core::Result<std::vector<ComplianceFinding>>::err(
            ThreatOne::Core::Error("No controls found for framework",
                                   ThreatOne::Core::ErrorCategory::Validation));
    }

    std::vector<ComplianceFinding> scanFindings;
    scanFindings.reserve(controls.size());

    for (const auto& control : controls) {
        auto finding = scanControl(control, state);
        scanFindings.push_back(finding);
        findings_.push_back(finding);
    }

    scanCount_++;
    logger_.info("Completed scan of framework with {} findings", scanFindings.size());

    return ThreatOne::Core::Result<std::vector<ComplianceFinding>>::ok(scanFindings);
}

std::vector<ComplianceFinding> ComplianceScanner::getFindings() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return findings_;
}

std::vector<ComplianceFinding> ComplianceScanner::getFindingsByStatus(FindingStatus status) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ComplianceFinding> result;
    for (const auto& f : findings_) {
        if (f.status == status) result.push_back(f);
    }
    return result;
}

std::vector<ComplianceFinding> ComplianceScanner::getFindingsByFramework(Framework framework) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ComplianceFinding> result;
    for (const auto& f : findings_) {
        if (f.framework == framework) result.push_back(f);
    }
    return result;
}

void ComplianceScanner::clearFindings() {
    std::lock_guard<std::mutex> lock(mutex_);
    findings_.clear();
}

size_t ComplianceScanner::getScanCount() const {
    return scanCount_.load();
}

} // namespace ThreatOne::Compliance
