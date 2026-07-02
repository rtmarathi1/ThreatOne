#pragma once

#include "siem/ISIEMEngine.h"
#include "core/Logger.h"

#include <mutex>
#include <string>
#include <vector>
#include <unordered_map>

namespace ThreatOne::SIEM {

// Canonical field names for normalization
struct NormalizedEvent {
    std::string timestamp;
    std::string source;
    std::string severity;
    std::string message;
    std::string srcIp;
    std::string dstIp;
    std::string user;
    std::string action;
    std::string eventType;
    std::string hostname;
    std::string application;
    std::unordered_map<std::string, std::string> additionalFields;
};

class EventNormalizer {
public:
    EventNormalizer();
    ~EventNormalizer() = default;

    // Normalize parsed fields into a canonical event
    [[nodiscard]] NormalizedEvent normalize(const std::vector<ParsedField>& fields,
                                           const std::string& source = "",
                                           const std::string& severity = "") const;

    // Convert normalized event back to a LogEntry for storage
    [[nodiscard]] LogEntry toLogEntry(const NormalizedEvent& event) const;

    // Add a field mapping (alias -> canonical name)
    void addFieldMapping(const std::string& alias, const std::string& canonical);

    // Get current field mappings
    [[nodiscard]] std::unordered_map<std::string, std::string> getFieldMappings() const;

private:
    [[nodiscard]] std::string mapFieldName(const std::string& name) const;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::string> fieldMappings_;
    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::SIEM
