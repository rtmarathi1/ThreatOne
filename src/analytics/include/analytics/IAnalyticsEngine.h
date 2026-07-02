#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace ThreatOne::Analytics {

struct AnalyticsMetric {
    std::string name;
    double value = 0.0;
    std::string unit;
    std::string timestamp;
};

struct TrendData {
    std::string metric;
    std::vector<double> values;
    std::vector<std::string> timestamps;
    std::string direction;
};

struct ThreatSummary {
    std::string name;
    uint64_t count = 0;
    std::string severity;
    double trend = 0.0;
};

struct SecurityPosture {
    double overallScore = 0.0;
    std::unordered_map<std::string, double> categoryScores;
    std::vector<std::string> recommendations;
};

class IAnalyticsEngine {
public:
    virtual ~IAnalyticsEngine() = default;

    virtual std::vector<AnalyticsMetric> getMetrics() = 0;
    virtual std::vector<TrendData> getTrends(const std::string& period) = 0;
    virtual std::vector<ThreatSummary> getTopThreats(int limit) = 0;
    virtual double getRiskScore() = 0;
    virtual SecurityPosture getSecurityPosture() = 0;
};

} // namespace ThreatOne::Analytics
