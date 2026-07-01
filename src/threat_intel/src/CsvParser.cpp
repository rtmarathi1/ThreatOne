#include "threat_intel/CsvParser.h"

#include <sstream>
#include <chrono>

namespace ThreatOne::ThreatIntel {

CsvParser::CsvParser(CsvParserConfig config)
    : config_(std::move(config)) {
}

std::vector<std::string> CsvParser::splitLine(const std::string& line, char delimiter) {
    std::vector<std::string> fields;
    std::string field;
    bool inQuotes = false;

    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (c == '"') {
            inQuotes = !inQuotes;
        } else if (c == delimiter && !inQuotes) {
            // Trim whitespace from field
            size_t start = field.find_first_not_of(" \t");
            size_t end = field.find_last_not_of(" \t");
            if (start != std::string::npos) {
                fields.push_back(field.substr(start, end - start + 1));
            } else {
                fields.emplace_back("");
            }
            field.clear();
        } else {
            field += c;
        }
    }

    // Add last field
    size_t start = field.find_first_not_of(" \t\r\n");
    size_t end = field.find_last_not_of(" \t\r\n");
    if (start != std::string::npos) {
        fields.push_back(field.substr(start, end - start + 1));
    } else {
        fields.emplace_back("");
    }

    return fields;
}

Core::Result<std::vector<IOC>> CsvParser::parse(const std::string& data) {
    std::vector<IOC> results;
    std::istringstream stream(data);
    std::string line;
    bool firstLine = true;

    auto now = std::chrono::system_clock::now();

    while (std::getline(stream, line)) {
        // Skip empty lines
        if (line.empty() || line.find_first_not_of(" \t\r\n") == std::string::npos) {
            continue;
        }

        // Skip comment lines
        if (line[0] == '#') {
            continue;
        }

        // Skip header line if configured
        if (firstLine && config_.hasHeader) {
            firstLine = false;
            continue;
        }
        firstLine = false;

        auto fields = splitLine(line, config_.delimiter);

        // Need at least type and value columns
        int maxRequired = std::max(config_.typeColumn, config_.valueColumn);
        if (static_cast<int>(fields.size()) <= maxRequired) {
            continue; // Skip malformed lines
        }

        IOC ioc;
        ioc.active = true;
        ioc.firstSeen = now;
        ioc.lastSeen = now;

        // Extract type
        if (config_.typeColumn >= 0 &&
            config_.typeColumn < static_cast<int>(fields.size())) {
            ioc.type = iocTypeFromString(fields[static_cast<size_t>(config_.typeColumn)]);
        }

        // Extract value
        if (config_.valueColumn >= 0 &&
            config_.valueColumn < static_cast<int>(fields.size())) {
            ioc.value = fields[static_cast<size_t>(config_.valueColumn)];
        }

        if (ioc.value.empty()) {
            continue;
        }

        // Extract optional confidence
        if (config_.confidenceColumn >= 0 &&
            config_.confidenceColumn < static_cast<int>(fields.size())) {
            try {
                ioc.confidence = std::stod(fields[static_cast<size_t>(config_.confidenceColumn)]);
                if (ioc.confidence > 1.0) ioc.confidence = 1.0;
                if (ioc.confidence < 0.0) ioc.confidence = 0.0;
            } catch (...) {
                ioc.confidence = 0.5;
            }
        }

        // Extract optional source
        if (config_.sourceColumn >= 0 &&
            config_.sourceColumn < static_cast<int>(fields.size())) {
            ioc.source = fields[static_cast<size_t>(config_.sourceColumn)];
        } else {
            ioc.source = "CSV Feed";
        }

        // Extract optional severity
        if (config_.severityColumn >= 0 &&
            config_.severityColumn < static_cast<int>(fields.size())) {
            ioc.severity = iocSeverityFromString(fields[static_cast<size_t>(config_.severityColumn)]);
        } else {
            // Default severity based on confidence
            if (ioc.confidence >= 0.8) ioc.severity = IOCSeverity::Critical;
            else if (ioc.confidence >= 0.6) ioc.severity = IOCSeverity::High;
            else if (ioc.confidence >= 0.3) ioc.severity = IOCSeverity::Medium;
            else ioc.severity = IOCSeverity::Low;
        }

        results.push_back(std::move(ioc));
    }

    return Core::Result<std::vector<IOC>>::ok(std::move(results));
}

} // namespace ThreatOne::ThreatIntel
