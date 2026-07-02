#include "threat_intel/IntelReportGenerator.h"

#include <nlohmann/json.hpp>
#include <algorithm>
#include <chrono>
#include <sstream>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ThreatOne::ThreatIntel {

IntelReportGenerator::IntelReportGenerator()
    : logger_(Core::Logger::instance().getModuleLogger("ThreatIntel.ReportGenerator")) {
}

IntelReport IntelReportGenerator::generateReport(
    const IOCManager& iocManager,
    const ThreatCorrelationEngine& correlationEngine,
    const ThreatScoringEngine& scoringEngine) const {

    IntelReport report;
    report.id = "RPT-" + std::to_string(
        std::chrono::system_clock::now().time_since_epoch().count());
    report.title = "Threat Intelligence Summary Report";
    report.generatedAt = std::chrono::system_clock::now();

    // Generate threat landscape section
    auto landscapeSection = generateThreatLandscape(iocManager);
    report.sections.push_back(landscapeSection);

    // Get top threats
    report.topThreats = getTopThreats(iocManager, scoringEngine, 10);

    // Get trending indicators (last 24 hours)
    report.trendingIndicators = getTrendingIndicators(iocManager, std::chrono::hours(24));

    // Correlate IOCs to identify campaigns
    auto allIOCs = iocManager.getActiveIOCs();
    auto campaigns = correlationEngine.correlateIOCs(allIOCs);

    // Add campaigns section
    ReportSection campaignSection;
    campaignSection.title = "Active Campaigns";
    campaignSection.content = "Campaigns identified through IOC correlation.";
    campaignSection.data["campaign_count"] = std::to_string(campaigns.size());
    for (size_t i = 0; i < campaigns.size() && i < 5; ++i) {
        campaignSection.data["campaign_" + std::to_string(i)] = campaigns[i].name;
    }
    report.sections.push_back(campaignSection);

    // Statistics
    report.statistics["total_iocs"] = iocManager.size();
    report.statistics["active_iocs"] = allIOCs.size();
    report.statistics["top_threats_count"] = report.topThreats.size();
    report.statistics["trending_count"] = report.trendingIndicators.size();
    report.statistics["campaigns_detected"] = campaigns.size();
    report.statistics["correlation_rules"] = correlationEngine.ruleCount();

    // Build summary
    std::ostringstream summary;
    summary << "Total IOCs: " << iocManager.size()
            << ", Active: " << allIOCs.size()
            << ", Campaigns: " << campaigns.size()
            << ", Top Threats: " << report.topThreats.size();
    report.summary = summary.str();

    logger_.info("Generated report with {} sections, {} top threats",
                 report.sections.size(), report.topThreats.size());

    return report;
}

ReportSection IntelReportGenerator::generateThreatLandscape(const IOCManager& iocManager) const {
    ReportSection section;
    section.title = "Threat Landscape";
    section.content = "Current IOC distribution by type and severity.";

    auto allIOCs = iocManager.getAllIOCs();

    // Count by type
    std::unordered_map<std::string, size_t> typeCounts;
    std::unordered_map<std::string, size_t> severityCounts;

    for (const auto& ioc : allIOCs) {
        typeCounts[iocTypeToString(ioc.type)]++;
        severityCounts[iocSeverityToString(ioc.severity)]++;
    }

    for (const auto& [type, count] : typeCounts) {
        section.data["type_" + type] = std::to_string(count);
    }
    for (const auto& [severity, count] : severityCounts) {
        section.data["severity_" + severity] = std::to_string(count);
    }
    section.data["total"] = std::to_string(allIOCs.size());

    return section;
}

std::vector<IOC> IntelReportGenerator::getTopThreats(
    const IOCManager& iocManager,
    const ThreatScoringEngine& scoringEngine,
    size_t count) const {

    auto allIOCs = iocManager.getActiveIOCs();

    // Score all IOCs and sort by score
    std::vector<std::pair<double, IOC>> scoredIOCs;
    scoredIOCs.reserve(allIOCs.size());

    for (const auto& ioc : allIOCs) {
        auto score = scoringEngine.calculateScore(ioc);
        scoredIOCs.emplace_back(score.overallScore, ioc);
    }

    // Sort descending by score
    std::sort(scoredIOCs.begin(), scoredIOCs.end(),
              [](const auto& a, const auto& b) {
                  return a.first > b.first;
              });

    // Take top N
    std::vector<IOC> topThreats;
    for (size_t i = 0; i < count && i < scoredIOCs.size(); ++i) {
        topThreats.push_back(scoredIOCs[i].second);
    }

    return topThreats;
}

std::vector<IOC> IntelReportGenerator::getTrendingIndicators(
    const IOCManager& iocManager,
    std::chrono::hours timeWindow) const {

    auto allIOCs = iocManager.getActiveIOCs();
    auto now = std::chrono::system_clock::now();

    std::vector<IOC> trending;
    for (const auto& ioc : allIOCs) {
        auto age = std::chrono::duration_cast<std::chrono::hours>(now - ioc.lastSeen);
        if (age <= timeWindow) {
            trending.push_back(ioc);
        }
    }

    // Sort by lastSeen (most recent first)
    std::sort(trending.begin(), trending.end(),
              [](const IOC& a, const IOC& b) {
                  return a.lastSeen > b.lastSeen;
              });

    return trending;
}

nlohmann::json IntelReportGenerator::toJson(const IntelReport& report) const {
    nlohmann::json j;
    j["id"] = report.id;
    j["title"] = report.title;
    j["summary"] = report.summary;

    auto epochMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        report.generatedAt.time_since_epoch()).count();
    j["generatedAt"] = epochMs;

    // Sections
    nlohmann::json sectionsArr = nlohmann::json::array();
    for (const auto& section : report.sections) {
        nlohmann::json sectionJson;
        sectionJson["title"] = section.title;
        sectionJson["content"] = section.content;
        nlohmann::json dataJson = nlohmann::json::object();
        for (const auto& [key, value] : section.data) {
            dataJson[key] = value;
        }
        sectionJson["data"] = dataJson;
        sectionsArr.push_back(sectionJson);
    }
    j["sections"] = sectionsArr;

    // Top threats
    nlohmann::json threatsArr = nlohmann::json::array();
    for (const auto& ioc : report.topThreats) {
        nlohmann::json iocJson;
        iocJson["id"] = static_cast<int64_t>(ioc.id);
        iocJson["type"] = iocTypeToString(ioc.type);
        iocJson["value"] = ioc.value;
        iocJson["severity"] = iocSeverityToString(ioc.severity);
        iocJson["confidence"] = ioc.confidence;
        iocJson["source"] = ioc.source;
        threatsArr.push_back(iocJson);
    }
    j["topThreats"] = threatsArr;

    // Trending indicators
    nlohmann::json trendingArr = nlohmann::json::array();
    for (const auto& ioc : report.trendingIndicators) {
        nlohmann::json iocJson;
        iocJson["id"] = static_cast<int64_t>(ioc.id);
        iocJson["type"] = iocTypeToString(ioc.type);
        iocJson["value"] = ioc.value;
        iocJson["severity"] = iocSeverityToString(ioc.severity);
        trendingArr.push_back(iocJson);
    }
    j["trendingIndicators"] = trendingArr;

    // Statistics
    nlohmann::json statsJson = nlohmann::json::object();
    for (const auto& [key, value] : report.statistics) {
        statsJson[key] = static_cast<int64_t>(value);
    }
    j["statistics"] = statsJson;

    return j;
}

} // namespace ThreatOne::ThreatIntel
