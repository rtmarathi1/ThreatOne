#include "threat_intel/OpenIOCParser.h"

#include <chrono>
#include <algorithm>

namespace ThreatOne::ThreatIntel {

std::string OpenIOCParser::extractTagContent(const std::string& xml,
                                             const std::string& tag,
                                             size_t startPos) {
    std::string openTag = "<" + tag;
    std::string closeTag = "</" + tag + ">";

    auto openPos = xml.find(openTag, startPos);
    if (openPos == std::string::npos) return "";

    // Find end of opening tag (handle attributes)
    auto tagEnd = xml.find('>', openPos);
    if (tagEnd == std::string::npos) return "";

    // Check for self-closing tag
    if (xml[tagEnd - 1] == '/') return "";

    auto closePos = xml.find(closeTag, tagEnd + 1);
    if (closePos == std::string::npos) return "";

    return xml.substr(tagEnd + 1, closePos - tagEnd - 1);
}

std::vector<std::pair<std::string, std::string>>
OpenIOCParser::extractIndicatorItems(const std::string& xml) {
    std::vector<std::pair<std::string, std::string>> items;

    // Look for IndicatorItem elements
    // Format: <IndicatorItem ...>
    //           <Context document="..." search="...Type" />
    //           <Content type="...">VALUE</Content>
    //         </IndicatorItem>

    const std::string itemTag = "<IndicatorItem";
    const std::string itemClose = "</IndicatorItem>";

    size_t pos = 0;
    while ((pos = xml.find(itemTag, pos)) != std::string::npos) {
        auto endPos = xml.find(itemClose, pos);
        if (endPos == std::string::npos) break;

        std::string itemXml = xml.substr(pos, endPos - pos + itemClose.size());

        // Extract the Context search attribute for type detection
        std::string typeStr;
        auto contextPos = itemXml.find("<Context");
        if (contextPos != std::string::npos) {
            auto searchPos = itemXml.find("search=\"", contextPos);
            if (searchPos != std::string::npos) {
                searchPos += 8; // length of search="
                auto searchEnd = itemXml.find('"', searchPos);
                if (searchEnd != std::string::npos) {
                    typeStr = itemXml.substr(searchPos, searchEnd - searchPos);
                }
            }
        }

        // Extract the Content value
        std::string value = extractTagContent(itemXml, "Content");

        // Trim the value
        size_t start = value.find_first_not_of(" \t\r\n");
        size_t end = value.find_last_not_of(" \t\r\n");
        if (start != std::string::npos && end != std::string::npos) {
            value = value.substr(start, end - start + 1);
        }

        if (!value.empty()) {
            items.emplace_back(typeStr, value);
        }

        pos = endPos + itemClose.size();
    }

    return items;
}

Core::Result<std::vector<IOC>> OpenIOCParser::parse(const std::string& data) {
    std::vector<IOC> results;

    if (data.empty()) {
        return Core::Result<std::vector<IOC>>::ok(std::move(results));
    }

    auto items = extractIndicatorItems(data);
    auto now = std::chrono::system_clock::now();

    for (const auto& [typeHint, value] : items) {
        IOC ioc;
        ioc.value = value;
        ioc.source = "OpenIOC Feed";
        ioc.confidence = 0.6;
        ioc.severity = IOCSeverity::Medium;
        ioc.firstSeen = now;
        ioc.lastSeen = now;
        ioc.active = true;

        // Determine type from Context search attribute
        std::string lowerType = typeHint;
        std::transform(lowerType.begin(), lowerType.end(), lowerType.begin(),
                       [](unsigned char c) { return std::tolower(c); });

        if (lowerType.find("ip") != std::string::npos ||
            lowerType.find("address") != std::string::npos) {
            ioc.type = IOCType::IP;
        } else if (lowerType.find("domain") != std::string::npos ||
                   lowerType.find("dns") != std::string::npos) {
            ioc.type = IOCType::Domain;
        } else if (lowerType.find("md5") != std::string::npos) {
            ioc.type = IOCType::Hash_MD5;
        } else if (lowerType.find("sha1") != std::string::npos) {
            ioc.type = IOCType::Hash_SHA1;
        } else if (lowerType.find("sha256") != std::string::npos ||
                   lowerType.find("sha-256") != std::string::npos) {
            ioc.type = IOCType::Hash_SHA256;
        } else if (lowerType.find("url") != std::string::npos ||
                   lowerType.find("uri") != std::string::npos) {
            ioc.type = IOCType::URL;
        } else if (lowerType.find("email") != std::string::npos) {
            ioc.type = IOCType::EmailAddress;
        } else if (lowerType.find("file") != std::string::npos ||
                   lowerType.find("path") != std::string::npos) {
            ioc.type = IOCType::FilePath;
        } else {
            // Auto-detect from value format
            ioc.type = IOCType::Domain; // default
            // Try hash detection by length
            bool isHex = !value.empty() &&
                std::all_of(value.begin(), value.end(), [](char c) {
                    return (c >= '0' && c <= '9') ||
                           (c >= 'a' && c <= 'f') ||
                           (c >= 'A' && c <= 'F');
                });
            if (isHex) {
                if (value.size() == 32) ioc.type = IOCType::Hash_MD5;
                else if (value.size() == 40) ioc.type = IOCType::Hash_SHA1;
                else if (value.size() == 64) ioc.type = IOCType::Hash_SHA256;
            }
        }

        results.push_back(std::move(ioc));
    }

    return Core::Result<std::vector<IOC>>::ok(std::move(results));
}

} // namespace ThreatOne::ThreatIntel
