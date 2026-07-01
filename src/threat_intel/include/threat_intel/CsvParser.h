#pragma once

// ThreatOne Threat Intel - CSV Feed Parser
// Parses CSV data with configurable column mapping

#include <string>
#include <vector>
#include <unordered_map>

#include "IFeedParser.h"

namespace ThreatOne::ThreatIntel {

// Configuration for CSV column mapping
struct CsvParserConfig {
    char delimiter = ',';
    bool hasHeader = true;
    // Column indices (0-based) for IOC fields
    int typeColumn = 0;
    int valueColumn = 1;
    int confidenceColumn = 2;   // -1 if not present
    int sourceColumn = 3;       // -1 if not present
    int severityColumn = -1;    // -1 if not present
};

// Parser for CSV format threat feeds
class CsvParser : public IFeedParser {
public:
    explicit CsvParser(CsvParserConfig config = CsvParserConfig{});

    [[nodiscard]] Core::Result<std::vector<IOC>> parse(const std::string& data) override;

private:
    // Split a single CSV line into fields
    static std::vector<std::string> splitLine(const std::string& line, char delimiter);

    CsvParserConfig config_;
};

} // namespace ThreatOne::ThreatIntel
