#pragma once

// ThreatOne Threat Intel - Intel Report Generator
// Generates threat intelligence reports summarizing current threat landscape

#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>

#include <core/Error.h>
#include <core/Logger.h>
#include "IOCTypes.h"
#include "IOCManager.h"
#include "ThreatCorrelation.h"
#include "ThreatScoring.h"

namespace ThreatOne::ThreatIntel {

// A section within an intel report
struct ReportSection {
    std::string title;
    std::string content;
    std::unordered_map<std::string, std::string> data;
};

// Complete intelligence report
struct IntelReport {
    std::string id;
    std::string title;
    std::chrono::system_clock::time_point generatedAt;
    std::string summary;
    std::vector<ReportSection> sections;
    std::vector<IOC> topThreats;
    std::vector<IOC> trendingIndicators;
    std::unordered_map<std::string, size_t> statistics;
};

} // namespace ThreatOne::ThreatIntel

// Forward declare nlohmann::json to avoid including the full header
namespace nlohmann { class json; }

namespace ThreatOne::ThreatIntel {

// Generates comprehensive threat intelligence reports
class IntelReportGenerator {
public:
    IntelReportGenerator();

    // Generate a full report using data from all components
    [[nodiscard]] IntelReport generateReport(
        const IOCManager& iocManager,
        const ThreatCorrelationEngine& correlationEngine,
        const ThreatScoringEngine& scoringEngine) const;

    // Generate a threat landscape section summarizing IOC counts by type/severity
    [[nodiscard]] ReportSection generateThreatLandscape(const IOCManager& iocManager) const;

    // Get top threats ranked by score
    [[nodiscard]] std::vector<IOC> getTopThreats(
        const IOCManager& iocManager,
        const ThreatScoringEngine& scoringEngine,
        size_t count = 10) const;

    // Get recently added/updated IOCs within a time window
    [[nodiscard]] std::vector<IOC> getTrendingIndicators(
        const IOCManager& iocManager,
        std::chrono::hours timeWindow = std::chrono::hours(24)) const;

    // Serialize a report to JSON
    [[nodiscard]] nlohmann::json toJson(const IntelReport& report) const;

private:
    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::ThreatIntel
