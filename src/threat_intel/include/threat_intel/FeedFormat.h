#pragma once

// ThreatOne Threat Intel - Feed Format Types
// Defines supported feed formats and feed configuration

#include <string>
#include <chrono>

namespace ThreatOne::ThreatIntel {

// Supported feed formats
enum class FeedFormat {
    STIX_JSON,
    CSV,
    PlainText,
    OpenIOC_XML
};

// Convert FeedFormat to/from string
inline std::string feedFormatToString(FeedFormat format) {
    switch (format) {
        case FeedFormat::STIX_JSON:    return "STIX_JSON";
        case FeedFormat::CSV:          return "CSV";
        case FeedFormat::PlainText:    return "PlainText";
        case FeedFormat::OpenIOC_XML:  return "OpenIOC_XML";
    }
    return "Unknown";
}

inline FeedFormat feedFormatFromString(const std::string& str) {
    if (str == "STIX_JSON" || str == "stix") return FeedFormat::STIX_JSON;
    if (str == "CSV" || str == "csv") return FeedFormat::CSV;
    if (str == "PlainText" || str == "plaintext" || str == "txt") return FeedFormat::PlainText;
    if (str == "OpenIOC_XML" || str == "openioc" || str == "xml") return FeedFormat::OpenIOC_XML;
    return FeedFormat::PlainText; // default fallback
}

// Configuration for a threat intelligence feed
struct FeedConfig {
    uint64_t id = 0;
    std::string name;
    std::string url;
    FeedFormat format = FeedFormat::PlainText;
    std::chrono::seconds refreshInterval{3600}; // default 1 hour
    bool enabled = true;
    std::chrono::system_clock::time_point lastRefresh;
    std::string credentials; // optional auth token or credentials
};

} // namespace ThreatOne::ThreatIntel
