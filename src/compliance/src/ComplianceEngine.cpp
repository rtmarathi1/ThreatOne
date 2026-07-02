#include "compliance/ComplianceEngine.h"

#include <sstream>
#include <string>
#include <vector>

namespace ThreatOne::Compliance {

ComplianceEngine::ComplianceEngine()
    : scanner_(framework_)
    , logger_("ComplianceEngine") {
    logger_.info("ComplianceEngine initialized");
}

AuditResult ComplianceEngine::runAudit(Framework fw) {
    logger_.info("Running audit for framework {}", static_cast<int>(fw));

    SystemState defaultState;
    auto scanResult = scanner_.scan(fw, defaultState);

    AuditResult result;
    result.id = "AUDIT-" + std::to_string(static_cast<int>(fw));
    result.framework = fw;

    if (scanResult.isOk()) {
        result.findings = scanResult.value();
        auto categories = framework_.getCategories(fw);
        auto score = scoring_.calculateScore(fw, result.findings, categories);
        result.score = score.overallScore;
        scoring_.recordScore(fw, result.score);
    } else {
        result.score = 0.0;
    }

    result.timestamp = "";
    logger_.info("Audit complete: score={}", result.score);
    return result;
}

std::vector<FrameworkInfo> ComplianceEngine::getFrameworks() {
    return framework_.getFrameworkInfos();
}

std::vector<ControlInfo> ComplianceEngine::getControls(Framework fw) {
    return framework_.getControls(fw);
}

double ComplianceEngine::getComplianceScore(Framework fw) {
    auto latestScore = scoring_.getLatestScore(fw);
    if (latestScore.has_value()) {
        return latestScore.value();
    }
    // Run audit if no score recorded yet
    auto audit = runAudit(fw);
    return audit.score;
}

std::string ComplianceEngine::generateReport(Framework fw) {
    logger_.info("Generating compliance report for framework {}", static_cast<int>(fw));

    std::ostringstream oss;
    oss << "=== Compliance Report ===\n";
    oss << "Framework: " << ComplianceFramework::frameworkToString(fw) << "\n\n";

    auto controls = framework_.getControls(fw);
    oss << "Total Controls: " << controls.size() << "\n";

    auto latestScore = scoring_.getLatestScore(fw);
    if (latestScore.has_value()) {
        oss << "Compliance Score: " << latestScore.value() << "%\n";
    }

    oss << "\n--- Controls ---\n";
    for (const auto& ctrl : controls) {
        oss << ctrl.id << ": " << ctrl.name;
        oss << (ctrl.implemented ? " [Implemented]" : " [Not Implemented]");
        oss << "\n";
    }

    return oss.str();
}

} // namespace ThreatOne::Compliance
