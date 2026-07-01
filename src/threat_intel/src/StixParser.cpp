#include "threat_intel/StixParser.h"

#include <nlohmann/json.hpp>
#include <chrono>
#include <stdexcept>

namespace ThreatOne::ThreatIntel {

bool StixParser::extractFromPattern(const std::string& pattern,
                                    IOCType& outType,
                                    std::string& outValue) {
    // STIX 2.1 pattern format: [type:property = 'value']
    // Examples:
    //   [ipv4-addr:value = '192.168.1.1']
    //   [domain-name:value = 'evil.com']
    //   [file:hashes.'SHA-256' = 'abc123...']
    //   [url:value = 'http://malware.com/payload']
    //   [email-addr:value = 'bad@evil.com']

    // Find the type (before the colon)
    auto colonPos = pattern.find(':');
    if (colonPos == std::string::npos || colonPos < 2) {
        return false;
    }

    // Extract type string (skip leading '[')
    size_t typeStart = (pattern.front() == '[') ? 1 : 0;
    std::string typeStr = pattern.substr(typeStart, colonPos - typeStart);

    // Find the value between single quotes after the '= ' operator
    // Look for the "= '" marker to locate the value's opening quote,
    // avoiding property path quotes like hashes.'SHA-256'
    auto eqPos = pattern.find("= '");
    if (eqPos == std::string::npos) return false;
    auto firstQuote = eqPos + 2; // position of the opening quote after "= "
    auto lastQuote = pattern.find('\'', firstQuote + 1);
    if (lastQuote == std::string::npos) return false;

    outValue = pattern.substr(firstQuote + 1, lastQuote - firstQuote - 1);

    // Determine IOC type from STIX type
    if (typeStr == "ipv4-addr" || typeStr == "ipv6-addr") {
        outType = IOCType::IP;
    } else if (typeStr == "domain-name") {
        outType = IOCType::Domain;
    } else if (typeStr == "url") {
        outType = IOCType::URL;
    } else if (typeStr == "email-addr") {
        outType = IOCType::EmailAddress;
    } else if (typeStr == "file") {
        // Determine hash type from pattern property
        if (pattern.find("MD5") != std::string::npos) {
            outType = IOCType::Hash_MD5;
        } else if (pattern.find("SHA-1") != std::string::npos ||
                   pattern.find("SHA1") != std::string::npos) {
            outType = IOCType::Hash_SHA1;
        } else if (pattern.find("SHA-256") != std::string::npos ||
                   pattern.find("SHA256") != std::string::npos) {
            outType = IOCType::Hash_SHA256;
        } else if (pattern.find("name") != std::string::npos) {
            outType = IOCType::FilePath;
        } else {
            outType = IOCType::Hash_SHA256; // default hash type
        }
    } else {
        return false;
    }

    return !outValue.empty();
}

Core::Result<std::vector<IOC>> StixParser::parse(const std::string& data) {
    std::vector<IOC> results;

    nlohmann::json doc;
    try {
        doc = nlohmann::json::parse(data);
    } catch (const std::exception& ex) {
        return Core::Result<std::vector<IOC>>::err(
            Core::Error("Failed to parse STIX JSON: " + std::string(ex.what()),
                        Core::ErrorCategory::Validation));
    }

    // STIX 2.1 bundle format: { "type": "bundle", "objects": [...] }
    if (!doc.contains("objects") || !doc["objects"].is_array()) {
        return Core::Result<std::vector<IOC>>::err(
            Core::Error("Invalid STIX bundle: missing 'objects' array",
                        Core::ErrorCategory::Validation));
    }

    auto now = std::chrono::system_clock::now();
    const auto& objects = doc["objects"].get_array();

    for (const auto& obj : objects) {
        // Only process indicator objects
        if (!obj.contains("type") || obj["type"] != "indicator") {
            continue;
        }

        if (!obj.contains("pattern") || !obj["pattern"].is_string()) {
            continue;
        }

        std::string pattern = obj["pattern"].get<std::string>();
        IOCType iocType;
        std::string iocValue;

        if (!extractFromPattern(pattern, iocType, iocValue)) {
            continue;
        }

        IOC ioc;
        ioc.type = iocType;
        ioc.value = iocValue;
        ioc.source = "STIX Feed";
        ioc.firstSeen = now;
        ioc.lastSeen = now;
        ioc.active = true;

        // Extract optional fields
        if (obj.contains("confidence") && obj["confidence"].is_number()) {
            double conf = obj["confidence"].get<double>();
            // STIX confidence is 0-100, normalize to 0.0-1.0
            ioc.confidence = conf / 100.0;
            if (ioc.confidence > 1.0) ioc.confidence = 1.0;
            if (ioc.confidence < 0.0) ioc.confidence = 0.0;
        }

        if (obj.contains("name") && obj["name"].is_string()) {
            ioc.tags.push_back(obj["name"].get<std::string>());
        }

        if (obj.contains("description") && obj["description"].is_string()) {
            ioc.metadata["description"] = obj["description"].get<std::string>();
        }

        if (obj.contains("id") && obj["id"].is_string()) {
            ioc.metadata["stix_id"] = obj["id"].get<std::string>();
        }

        // Map confidence to severity
        if (ioc.confidence >= 0.8) {
            ioc.severity = IOCSeverity::Critical;
        } else if (ioc.confidence >= 0.6) {
            ioc.severity = IOCSeverity::High;
        } else if (ioc.confidence >= 0.3) {
            ioc.severity = IOCSeverity::Medium;
        } else {
            ioc.severity = IOCSeverity::Low;
        }

        results.push_back(std::move(ioc));
    }

    return Core::Result<std::vector<IOC>>::ok(std::move(results));
}

} // namespace ThreatOne::ThreatIntel
