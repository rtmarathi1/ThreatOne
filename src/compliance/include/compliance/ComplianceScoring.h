#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>

#include "compliance/IComplianceEngine.h"
#include "core/Logger.h"
#include <optional>

namespace ThreatOne::Compliance {

class ComplianceScoring {
public:
    ComplianceScoring();
    ~ComplianceScoring() = default;

    // Calculate score for a framework based on findings
    [[nodiscard]] FrameworkScore calculateScore(
        Framework framework,
        const std::vector<ComplianceFinding>& findings,
        const std::vector<ControlCategory>& categories) const;

    // Calculate overall score across all frameworks
    [[nodiscard]] double calculateOverallScore(
        const std::vector<FrameworkScore>& frameworkScores) const;

    // Record a score for trend tracking
    void recordScore(Framework framework, double score);

    // Get score history for trend analysis
    [[nodiscard]] std::vector<ScoreHistoryEntry> getScoreHistory(Framework framework) const;

    // Get the latest score for a framework
    [[nodiscard]] std::optional<double> getLatestScore(Framework framework) const;

    // Clear history for a framework
    void clearHistory(Framework framework);

    // Clear all history
    void clearAllHistory();

private:
    [[nodiscard]] std::string getCurrentTimestamp() const;
    [[nodiscard]] double calculateCategoryScore(
        const std::string& categoryId,
        const std::vector<ComplianceFinding>& findings) const;

    mutable std::mutex mutex_;
    std::map<Framework, std::vector<ScoreHistoryEntry>> scoreHistory_;
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Compliance
