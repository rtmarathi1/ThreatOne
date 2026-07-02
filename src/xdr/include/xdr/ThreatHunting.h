#pragma once

#include "xdr/IXDREngine.h"
#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>

namespace ThreatOne::XDR {

// Represents a threat hunting hypothesis
struct HuntingHypothesis {
    std::string id;
    std::string name;
    std::string description;
    std::string technique;     // MITRE ATT&CK technique ID (e.g., T1055)
    std::string dataSource;    // "endpoint", "network", "identity", "cloud", "all"
    std::string query;         // Search/query pattern
    std::string status;        // "draft", "active", "completed", "archived"
    std::vector<std::string> indicators;
};

// Represents an IOC (Indicator of Compromise)
struct IOC {
    std::string id;
    std::string type;    // "ip", "domain", "hash", "file_path", "registry_key", "email"
    std::string value;
    std::string source;  // "internal", "threat_intel", "manual"
    std::string severity;
    std::string timestamp;
    bool active = true;
};

// Represents a hunt result
struct HuntResult {
    std::string id;
    std::string hypothesisId;
    std::vector<std::string> matchedEventIds;
    std::vector<std::string> matchedIOCs;
    std::string summary;
    double confidence = 0.0;
    std::string severity;
    std::string timestamp;
};

// Represents a behavioral pattern for detection
struct BehavioralPattern {
    std::string id;
    std::string name;
    std::string description;
    std::vector<std::string> eventSequence;  // Expected sequence of event types
    int timeWindowSeconds = 3600;
    std::string severity;
};

class ThreatHunting {
public:
    ThreatHunting();
    ~ThreatHunting() = default;

    // Hypothesis management
    std::string createHypothesis(const HuntingHypothesis& hypothesis);
    [[nodiscard]] std::vector<HuntingHypothesis> getHypotheses(const std::string& status = "") const;
    bool updateHypothesisStatus(const std::string& id, const std::string& status);

    // IOC management
    std::string addIOC(const IOC& ioc);
    [[nodiscard]] std::vector<IOC> getIOCs(const std::string& type = "") const;
    bool deactivateIOC(const std::string& iocId);

    // IOC sweep - search events for IOC matches
    [[nodiscard]] std::vector<HuntResult> sweepIOCs(const std::vector<EndpointEvent>& events) const;

    // Behavioral pattern matching
    std::string addBehavioralPattern(const BehavioralPattern& pattern);
    [[nodiscard]] std::vector<HuntResult> matchBehavioralPatterns(const std::vector<EndpointEvent>& events) const;

    // Execute hunt
    HuntResult executeHunt(const std::string& hypothesisId, const std::vector<EndpointEvent>& events);

    // Results
    [[nodiscard]] std::vector<HuntResult> getHuntResults(const std::string& hypothesisId = "") const;

    // Stats
    [[nodiscard]] size_t getHypothesisCount() const;
    [[nodiscard]] size_t getIOCCount() const;
    [[nodiscard]] size_t getResultCount() const;

private:
    std::string generateHypothesisId();
    std::string generateIOCId();
    std::string generateResultId();
    std::string generatePatternId();

    mutable std::mutex mutex_;
    std::map<std::string, HuntingHypothesis> hypotheses_;
    std::map<std::string, IOC> iocs_;
    std::map<std::string, HuntResult> results_;
    std::map<std::string, BehavioralPattern> patterns_;
    int nextHypothesisId_ = 1;
    int nextIOCId_ = 1;
    int nextResultId_ = 1;
    int nextPatternId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::XDR
