#include "threat_intel/PlainTextParser.h"

#include <sstream>
#include <regex>
#include <chrono>
#include <algorithm>

namespace ThreatOne::ThreatIntel {

IOCType PlainTextParser::detectIOCType(const std::string& value) {
    // Check for URL (starts with http:// or https://)
    if (value.find("http://") == 0 || value.find("https://") == 0) {
        return IOCType::URL;
    }

    // Check for email address (contains @ with domain)
    if (value.find('@') != std::string::npos && value.find('.') != std::string::npos) {
        return IOCType::EmailAddress;
    }

    // Check for IP address (IPv4 pattern: digits.digits.digits.digits)
    {
        static const std::regex ipv4Regex(
            R"(^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$)");
        if (std::regex_match(value, ipv4Regex)) {
            return IOCType::IP;
        }
    }

    // Check for IPv6 (contains multiple colons)
    {
        auto colonCount = std::count(value.begin(), value.end(), ':');
        if (colonCount >= 2 && value.find('.') == std::string::npos) {
            return IOCType::IP;
        }
    }

    // Check for hash by length (hex-only characters)
    {
        bool isHex = !value.empty() &&
            std::all_of(value.begin(), value.end(), [](char c) {
                return (c >= '0' && c <= '9') ||
                       (c >= 'a' && c <= 'f') ||
                       (c >= 'A' && c <= 'F');
            });

        if (isHex) {
            if (value.size() == 32) return IOCType::Hash_MD5;
            if (value.size() == 40) return IOCType::Hash_SHA1;
            if (value.size() == 64) return IOCType::Hash_SHA256;
        }
    }

    // Check for file path (contains path separators)
    if (value.find('/') != std::string::npos || value.find('\\') != std::string::npos) {
        // But not if it looks like a URL we missed
        if (value.find("://") == std::string::npos) {
            return IOCType::FilePath;
        }
    }

    // Default to domain
    return IOCType::Domain;
}

Core::Result<std::vector<IOC>> PlainTextParser::parse(const std::string& data) {
    std::vector<IOC> results;
    std::istringstream stream(data);
    std::string line;
    auto now = std::chrono::system_clock::now();

    while (std::getline(stream, line)) {
        // Trim whitespace
        size_t start = line.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) continue;
        size_t end = line.find_last_not_of(" \t\r\n");
        line = line.substr(start, end - start + 1);

        // Skip empty lines and comments
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }

        IOC ioc;
        ioc.value = line;
        ioc.type = detectIOCType(line);
        ioc.source = "PlainText Feed";
        ioc.confidence = 0.5;
        ioc.severity = IOCSeverity::Medium;
        ioc.firstSeen = now;
        ioc.lastSeen = now;
        ioc.active = true;

        results.push_back(std::move(ioc));
    }

    return Core::Result<std::vector<IOC>>::ok(std::move(results));
}

} // namespace ThreatOne::ThreatIntel
