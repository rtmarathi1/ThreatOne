#pragma once

// ThreatOne Threat Intel - IOC (Indicator of Compromise) Types
// Defines IOC type enum and core IOC data structure

#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <cstdint>

namespace ThreatOne::ThreatIntel {

// Types of Indicators of Compromise
enum class IOCType {
    IP,
    Domain,
    Hash_MD5,
    Hash_SHA1,
    Hash_SHA256,
    URL,
    EmailAddress,
    FilePath
};

// Severity levels for IOCs
enum class IOCSeverity {
    Low,
    Medium,
    High,
    Critical
};

// Convert IOCType to/from string
inline std::string iocTypeToString(IOCType type) {
    switch (type) {
        case IOCType::IP:           return "IP";
        case IOCType::Domain:       return "Domain";
        case IOCType::Hash_MD5:     return "Hash_MD5";
        case IOCType::Hash_SHA1:    return "Hash_SHA1";
        case IOCType::Hash_SHA256:  return "Hash_SHA256";
        case IOCType::URL:          return "URL";
        case IOCType::EmailAddress: return "EmailAddress";
        case IOCType::FilePath:     return "FilePath";
    }
    return "Unknown";
}

inline IOCType iocTypeFromString(const std::string& str) {
    if (str == "IP" || str == "ipv4-addr" || str == "ipv6-addr") return IOCType::IP;
    if (str == "Domain" || str == "domain-name") return IOCType::Domain;
    if (str == "Hash_MD5" || str == "MD5") return IOCType::Hash_MD5;
    if (str == "Hash_SHA1" || str == "SHA1") return IOCType::Hash_SHA1;
    if (str == "Hash_SHA256" || str == "SHA256" || str == "SHA-256") return IOCType::Hash_SHA256;
    if (str == "URL" || str == "url") return IOCType::URL;
    if (str == "EmailAddress" || str == "email-addr") return IOCType::EmailAddress;
    if (str == "FilePath" || str == "file") return IOCType::FilePath;
    return IOCType::Domain; // default fallback
}

// Convert severity to/from string
inline std::string iocSeverityToString(IOCSeverity severity) {
    switch (severity) {
        case IOCSeverity::Low:      return "Low";
        case IOCSeverity::Medium:   return "Medium";
        case IOCSeverity::High:     return "High";
        case IOCSeverity::Critical: return "Critical";
    }
    return "Unknown";
}

inline IOCSeverity iocSeverityFromString(const std::string& str) {
    if (str == "Low" || str == "low") return IOCSeverity::Low;
    if (str == "Medium" || str == "medium") return IOCSeverity::Medium;
    if (str == "High" || str == "high") return IOCSeverity::High;
    if (str == "Critical" || str == "critical") return IOCSeverity::Critical;
    return IOCSeverity::Medium; // default fallback
}

// Core IOC data structure
struct IOC {
    uint64_t id = 0;
    IOCType type = IOCType::Domain;
    std::string value;
    std::string source;
    double confidence = 0.5;      // 0.0 - 1.0
    IOCSeverity severity = IOCSeverity::Medium;
    std::chrono::system_clock::time_point firstSeen;
    std::chrono::system_clock::time_point lastSeen;
    std::chrono::system_clock::time_point expirationDate;
    std::vector<std::string> tags;
    std::unordered_map<std::string, std::string> metadata;
    bool active = true;
};

} // namespace ThreatOne::ThreatIntel
