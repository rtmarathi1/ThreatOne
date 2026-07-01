#pragma once

// ThreatOne Threat Intel - STIX 2.1 JSON Parser
// Parses STIX 2.1 bundles and extracts indicator objects

#include "IFeedParser.h"

namespace ThreatOne::ThreatIntel {

// Parser for STIX 2.1 JSON bundle format
class StixParser : public IFeedParser {
public:
    StixParser() = default;

    [[nodiscard]] Core::Result<std::vector<IOC>> parse(const std::string& data) override;

private:
    // Extract IOC type and value from a STIX pattern string
    // e.g., "[ipv4-addr:value = '192.168.1.1']"
    static bool extractFromPattern(const std::string& pattern,
                                   IOCType& outType,
                                   std::string& outValue);
};

} // namespace ThreatOne::ThreatIntel
