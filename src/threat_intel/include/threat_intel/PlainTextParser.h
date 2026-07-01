#pragma once

// ThreatOne Threat Intel - Plain Text Feed Parser
// Parses one-indicator-per-line text, auto-detecting IOC type

#include "IFeedParser.h"

namespace ThreatOne::ThreatIntel {

// Parser for plain text indicator lists (one per line)
class PlainTextParser : public IFeedParser {
public:
    PlainTextParser() = default;

    [[nodiscard]] Core::Result<std::vector<IOC>> parse(const std::string& data) override;

    // Auto-detect the IOC type from its string value
    static IOCType detectIOCType(const std::string& value);
};

} // namespace ThreatOne::ThreatIntel
