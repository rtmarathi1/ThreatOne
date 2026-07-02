#include "siem/LogParser.h"

#include <regex>
#include <sstream>

namespace ThreatOne::SIEM {

LogParser::LogParser()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("LogParser")) {
    logger_.info("LogParser initialized");
}

std::vector<ParsedField> LogParser::parse(const std::string& rawLog, LogFormat format) const {
    switch (format) {
        case LogFormat::Syslog:
            return parseSyslog(rawLog);
        case LogFormat::JSON:
            return parseJSON(rawLog);
        case LogFormat::CEF:
            return parseCEF(rawLog);
        case LogFormat::LEEF:
            return parseLEEF(rawLog);
        case LogFormat::WindowsEventLog:
            return parseWindowsEventLog(rawLog);
    }
    return {};
}

std::vector<ParsedField> LogParser::parseSyslog(const std::string& rawLog) const {
    std::vector<ParsedField> fields;

    // Syslog format: <priority>timestamp hostname app[pid]: message
    // or simplified: Mon DD HH:MM:SS hostname app: message
    std::regex syslogRegex(R"(^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$)");
    std::smatch match;

    if (std::regex_match(rawLog, match, syslogRegex)) {
        fields.push_back({"timestamp", match[1].str(), "timestamp"});
        fields.push_back({"hostname", match[2].str(), "string"});
        fields.push_back({"application", match[3].str(), "string"});
        if (match[4].matched) {
            fields.push_back({"pid", match[4].str(), "integer"});
        }
        fields.push_back({"message", match[5].str(), "string"});
    } else {
        // Fallback: treat entire string as message
        fields.push_back({"raw_message", rawLog, "string"});
    }

    return fields;
}

std::vector<ParsedField> LogParser::parseJSON(const std::string& rawLog) const {
    std::vector<ParsedField> fields;

    // Simple JSON key-value extraction using regex
    // Matches: "key": "value" or "key": number
    std::regex jsonStringRegex(R"re("(\w+)"\s*:\s*"([^"]*)")re");
    std::regex jsonNumberRegex(R"re("(\w+)"\s*:\s*(\d+(?:\.\d+)?))re");

    auto strBegin = std::sregex_iterator(rawLog.begin(), rawLog.end(), jsonStringRegex);
    auto strEnd = std::sregex_iterator();
    for (auto it = strBegin; it != strEnd; ++it) {
        std::smatch m = *it;
        fields.push_back({m[1].str(), m[2].str(), "string"});
    }

    auto numBegin = std::sregex_iterator(rawLog.begin(), rawLog.end(), jsonNumberRegex);
    auto numEnd = std::sregex_iterator();
    for (auto it = numBegin; it != numEnd; ++it) {
        std::smatch m = *it;
        // Skip if already captured as string
        bool alreadyCaptured = false;
        for (const auto& f : fields) {
            if (f.name == m[1].str()) {
                alreadyCaptured = true;
                break;
            }
        }
        if (!alreadyCaptured) {
            fields.push_back({m[1].str(), m[2].str(), "integer"});
        }
    }

    return fields;
}

std::vector<ParsedField> LogParser::parseCEF(const std::string& rawLog) const {
    std::vector<ParsedField> fields;

    // CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    if (rawLog.substr(0, 4) != "CEF:") {
        fields.push_back({"raw_message", rawLog, "string"});
        return fields;
    }

    // Split by pipe '|'
    std::vector<std::string> parts;
    std::istringstream ss(rawLog.substr(4)); // skip "CEF:"
    std::string part;
    while (std::getline(ss, part, '|')) {
        parts.push_back(part);
    }

    if (parts.size() >= 7) {
        fields.push_back({"version", parts[0], "string"});
        fields.push_back({"device_vendor", parts[1], "string"});
        fields.push_back({"device_product", parts[2], "string"});
        fields.push_back({"device_version", parts[3], "string"});
        fields.push_back({"signature_id", parts[4], "string"});
        fields.push_back({"name", parts[5], "string"});
        fields.push_back({"severity", parts[6], "string"});

        // Extension key=value pairs
        if (parts.size() > 7) {
            std::string extension = parts[7];
            // For parts beyond 7 that may have been split by pipes in extension
            for (size_t i = 8; i < parts.size(); i++) {
                extension += "|" + parts[i];
            }

            std::regex kvRegex(R"((\w+)=([^\s]+))");
            auto kvBegin = std::sregex_iterator(extension.begin(), extension.end(), kvRegex);
            auto kvEnd = std::sregex_iterator();
            for (auto it = kvBegin; it != kvEnd; ++it) {
                std::smatch m = *it;
                fields.push_back({m[1].str(), m[2].str(), "string"});
            }
        }
    } else {
        fields.push_back({"raw_message", rawLog, "string"});
    }

    return fields;
}

std::vector<ParsedField> LogParser::parseLEEF(const std::string& rawLog) const {
    std::vector<ParsedField> fields;

    // LEEF format: LEEF:Version|Vendor|Product|Version|EventID|key=value\tkey=value
    if (rawLog.substr(0, 5) != "LEEF:") {
        fields.push_back({"raw_message", rawLog, "string"});
        return fields;
    }

    std::vector<std::string> parts;
    std::istringstream ss(rawLog.substr(5));
    std::string part;
    while (std::getline(ss, part, '|')) {
        parts.push_back(part);
    }

    if (parts.size() >= 5) {
        fields.push_back({"version", parts[0], "string"});
        fields.push_back({"vendor", parts[1], "string"});
        fields.push_back({"product", parts[2], "string"});
        fields.push_back({"product_version", parts[3], "string"});
        fields.push_back({"event_id", parts[4], "string"});

        // Key-value pairs separated by tab or space after the header
        if (parts.size() > 5) {
            std::string extension = parts[5];
            for (size_t i = 6; i < parts.size(); i++) {
                extension += "|" + parts[i];
            }

            std::regex kvRegex(R"((\w+)=([^\t]+))");
            auto kvBegin = std::sregex_iterator(extension.begin(), extension.end(), kvRegex);
            auto kvEnd = std::sregex_iterator();
            for (auto it = kvBegin; it != kvEnd; ++it) {
                std::smatch m = *it;
                fields.push_back({m[1].str(), m[2].str(), "string"});
            }
        }
    }

    return fields;
}

std::vector<ParsedField> LogParser::parseWindowsEventLog(const std::string& rawLog) const {
    std::vector<ParsedField> fields;

    // Windows Event Log simplified format: EventID=X Source=Y Level=Z Message=...
    std::regex kvRegex(R"((\w+)=([^\s]+(?:\s+[^\s=]+)*))");

    // Try key=value format first
    auto kvBegin = std::sregex_iterator(rawLog.begin(), rawLog.end(), kvRegex);
    auto kvEnd = std::sregex_iterator();
    for (auto it = kvBegin; it != kvEnd; ++it) {
        std::smatch m = *it;
        fields.push_back({m[1].str(), m[2].str(), "string"});
    }

    if (fields.empty()) {
        fields.push_back({"raw_message", rawLog, "string"});
    }

    return fields;
}

LogFormat LogParser::detectFormat(const std::string& rawLog) const {
    if (rawLog.substr(0, 4) == "CEF:") return LogFormat::CEF;
    if (rawLog.substr(0, 5) == "LEEF:") return LogFormat::LEEF;
    if (!rawLog.empty() && rawLog[0] == '{') return LogFormat::JSON;

    // Check for syslog pattern
    std::regex syslogPrefix(R"(^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+)");
    if (std::regex_search(rawLog, syslogPrefix)) return LogFormat::Syslog;

    // Check for Windows Event Log pattern (key=value)
    if (rawLog.find("EventID=") != std::string::npos ||
        rawLog.find("Source=") != std::string::npos) {
        return LogFormat::WindowsEventLog;
    }

    // Default to syslog
    return LogFormat::Syslog;
}

} // namespace ThreatOne::SIEM
