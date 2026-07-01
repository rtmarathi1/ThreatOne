#pragma once

#include <string>
#include <vector>

namespace ThreatOne::XDR {

struct Correlation {
    std::string id;
    std::string description;
    std::vector<std::string> eventIds;
    double confidence = 0.0;
    std::string severity;
};

struct TimelineEntry {
    std::string timestamp;
    std::string eventType;
    std::string description;
    std::string source;
};

struct Incident {
    std::string id;
    std::string title;
    std::string severity;
    std::string status;
    std::vector<std::string> correlationIds;
    std::vector<TimelineEntry> timeline;
};

class IXDREngine {
public:
    virtual ~IXDREngine() = default;

    virtual std::vector<Correlation> correlateEvents(const std::vector<std::string>& eventIds) = 0;
    virtual std::vector<Correlation> getCorrelations() = 0;
    virtual std::string startInvestigation(const std::string& correlationId) = 0;
    virtual std::vector<TimelineEntry> getTimeline(const std::string& investigationId) = 0;
    virtual std::vector<Incident> getIncidents() = 0;
};

} // namespace ThreatOne::XDR
