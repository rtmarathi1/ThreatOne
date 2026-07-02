#pragma once

// ThreatOne Threat Intel - OpenIOC XML Parser
// Parses OpenIOC-like XML format using simple string parsing (no external XML lib)

#include "IFeedParser.h"
#include <string>
#include <utility>
#include <vector>

namespace ThreatOne::ThreatIntel {

// Parser for OpenIOC-like XML format
class OpenIOCParser : public IFeedParser {
public:
    OpenIOCParser() = default;

    [[nodiscard]] Core::Result<std::vector<IOC>> parse(const std::string& data) override;

private:
    // Extract content between XML tags using simple string parsing
    static std::string extractTagContent(const std::string& xml,
                                         const std::string& tag,
                                         size_t startPos = 0);

    // Find all IndicatorItem elements and extract type/value
    static std::vector<std::pair<std::string, std::string>>
    extractIndicatorItems(const std::string& xml);
};

} // namespace ThreatOne::ThreatIntel
