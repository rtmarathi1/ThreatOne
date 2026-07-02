#pragma once

#include "siem/ISIEMEngine.h"
#include "core/Logger.h"

#include <mutex>
#include <string>
#include <vector>

namespace ThreatOne::SIEM {

class LogParser {
public:
    LogParser();
    ~LogParser() = default;

    // Parse a raw log string into structured fields based on format
    [[nodiscard]] std::vector<ParsedField> parse(const std::string& rawLog, LogFormat format) const;

    // Individual format parsers
    [[nodiscard]] std::vector<ParsedField> parseSyslog(const std::string& rawLog) const;
    [[nodiscard]] std::vector<ParsedField> parseJSON(const std::string& rawLog) const;
    [[nodiscard]] std::vector<ParsedField> parseCEF(const std::string& rawLog) const;
    [[nodiscard]] std::vector<ParsedField> parseLEEF(const std::string& rawLog) const;
    [[nodiscard]] std::vector<ParsedField> parseWindowsEventLog(const std::string& rawLog) const;

    // Auto-detect log format
    [[nodiscard]] LogFormat detectFormat(const std::string& rawLog) const;

private:
    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::SIEM
