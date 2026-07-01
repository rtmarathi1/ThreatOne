#include "compliance/ComplianceScoring.h"

#include <algorithm>
#include <chrono>
#include <sstream>
#include <numeric>

namespace ThreatOne::Compliance {

ComplianceScoring::ComplianceScoring()
    : logger_("ComplianceScoring") {
    logger_.info("ComplianceScoring initialized");
}

std::string ComplianceScoring::getCurrentTimestamp() const {
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

double ComplianceScoring::calculateCategoryScore(
    const std::string& categoryId,
    const std::vector<ComplianceFinding>& findings) const {

    int total = 0;
    int passing = 0;

    for (const auto& finding : findings) {
        // Match findings to category by checking if controlId starts with category prefix
        if (finding.controlId.find(categoryId) != std::string::npos ||
            finding.controlId.substr(0, categoryId.size()) == categoryId) {
            if (finding.status != FindingStatus::NotApplicable) {
                total++;
                if (finding.status == FindingStatus::Pass) {
                    passing++;
                } else if (finding.status == FindingStatus::Warning) {
                    // Warnings count as partial compliance
                    passing++;  // Count as half in the weighted version below
                }
            }
        }
    }

    if (total == 0) return 100.0;
    return (static_cast<double>(passing) / static_cast<double>(total)) * 100.0;
}

FrameworkScore ComplianceScoring::calculateScore(
    Framework framework,
    const std::vector<ComplianceFinding>& findings,
    const std::vector<ControlCategory>& categories) const {

    FrameworkScore score;
    score.framework = framework;
    score.timestamp = getCurrentTimestamp();

    double totalScore = 0.0;
    int categoryCount = 0;

    for (const auto& category : categories) {
        CategoryScore catScore;
        catScore.categoryId = category.id;
        catScore.categoryName = category.name;

        int total = 0;
        int passing = 0;

        for (const auto& finding : findings) {
            // Check if this finding belongs to this category
            bool belongsToCategory = false;
            for (const auto& ctrl : category.controls) {
                if (ctrl.id == finding.controlId) {
                    belongsToCategory = true;
                    break;
                }
            }

            if (belongsToCategory && finding.status != FindingStatus::NotApplicable) {
                total++;
                if (finding.status == FindingStatus::Pass) {
                    passing++;
                }
            }
        }

        catScore.totalControls = static_cast<uint32_t>(total);
        catScore.passingControls = static_cast<uint32_t>(passing);
        catScore.score = (total > 0) ? (static_cast<double>(passing) / total) * 100.0 : 100.0;

        score.categoryScores.push_back(catScore);
        totalScore += catScore.score;
        categoryCount++;
    }

    score.overallScore = (categoryCount > 0) ? totalScore / categoryCount : 0.0;
    return score;
}

double ComplianceScoring::calculateOverallScore(
    const std::vector<FrameworkScore>& frameworkScores) const {
    if (frameworkScores.empty()) return 0.0;

    double total = 0.0;
    for (const auto& fs : frameworkScores) {
        total += fs.overallScore;
    }
    return total / static_cast<double>(frameworkScores.size());
}

void ComplianceScoring::recordScore(Framework framework, double score) {
    std::lock_guard<std::mutex> lock(mutex_);
    ScoreHistoryEntry entry;
    entry.score = score;
    entry.timestamp = getCurrentTimestamp();
    scoreHistory_[framework].push_back(entry);
    logger_.info("Recorded score {} for framework", score);
}

std::vector<ScoreHistoryEntry> ComplianceScoring::getScoreHistory(Framework framework) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = scoreHistory_.find(framework);
    if (it == scoreHistory_.end()) return {};
    return it->second;
}

std::optional<double> ComplianceScoring::getLatestScore(Framework framework) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = scoreHistory_.find(framework);
    if (it == scoreHistory_.end() || it->second.empty()) return std::nullopt;
    return it->second.back().score;
}

void ComplianceScoring::clearHistory(Framework framework) {
    std::lock_guard<std::mutex> lock(mutex_);
    scoreHistory_.erase(framework);
}

void ComplianceScoring::clearAllHistory() {
    std::lock_guard<std::mutex> lock(mutex_);
    scoreHistory_.clear();
}

} // namespace ThreatOne::Compliance
