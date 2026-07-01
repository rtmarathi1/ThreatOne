#pragma once

// ThreatOne Threat Intel - Feed Parser Interface
// Abstract base for all feed format parsers

#include <string>
#include <vector>

#include <core/Error.h>
#include "IOCTypes.h"

namespace ThreatOne::ThreatIntel {

// Interface for feed data parsers
class IFeedParser {
public:
    virtual ~IFeedParser() = default;

    // Parse raw feed data into a list of IOCs
    [[nodiscard]] virtual Core::Result<std::vector<IOC>> parse(const std::string& data) = 0;
};

} // namespace ThreatOne::ThreatIntel
