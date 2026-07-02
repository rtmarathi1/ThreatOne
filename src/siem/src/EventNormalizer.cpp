#include "siem/EventNormalizer.h"
#include <unordered_map>
#include <mutex>

#include <algorithm>

namespace ThreatOne::SIEM {

EventNormalizer::EventNormalizer()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("EventNormalizer")) {
    // Initialize default field mappings (alias -> canonical)
    fieldMappings_["src"] = "src_ip";
    fieldMappings_["source_ip"] = "src_ip";
    fieldMappings_["sourceAddress"] = "src_ip";
    fieldMappings_["src_addr"] = "src_ip";
    fieldMappings_["dst"] = "dst_ip";
    fieldMappings_["dest_ip"] = "dst_ip";
    fieldMappings_["destinationAddress"] = "dst_ip";
    fieldMappings_["dst_addr"] = "dst_ip";
    fieldMappings_["username"] = "user";
    fieldMappings_["userName"] = "user";
    fieldMappings_["account"] = "user";
    fieldMappings_["login"] = "user";
    fieldMappings_["act"] = "action";
    fieldMappings_["activity"] = "action";
    fieldMappings_["operation"] = "action";
    fieldMappings_["host"] = "hostname";
    fieldMappings_["computer"] = "hostname";
    fieldMappings_["device"] = "hostname";
    fieldMappings_["app"] = "application";
    fieldMappings_["program"] = "application";
    fieldMappings_["process"] = "application";
    fieldMappings_["event_type"] = "event_type";
    fieldMappings_["eventType"] = "event_type";
    fieldMappings_["type"] = "event_type";

    logger_.info("EventNormalizer initialized with {} field mappings", fieldMappings_.size());
}

NormalizedEvent EventNormalizer::normalize(const std::vector<ParsedField>& fields,
                                           const std::string& source,
                                           const std::string& severity) const {
    std::lock_guard<std::mutex> lock(mutex_);

    NormalizedEvent event;
    event.source = source;
    event.severity = severity;

    for (const auto& field : fields) {
        std::string canonical = mapFieldName(field.name);

        if (canonical == "timestamp" || field.type == "timestamp") {
            event.timestamp = field.value;
        } else if (canonical == "src_ip") {
            event.srcIp = field.value;
        } else if (canonical == "dst_ip") {
            event.dstIp = field.value;
        } else if (canonical == "user") {
            event.user = field.value;
        } else if (canonical == "action") {
            event.action = field.value;
        } else if (canonical == "hostname") {
            event.hostname = field.value;
        } else if (canonical == "application") {
            event.application = field.value;
        } else if (canonical == "event_type") {
            event.eventType = field.value;
        } else if (canonical == "message") {
            event.message = field.value;
        } else if (canonical == "severity") {
            event.severity = field.value;
        } else {
            event.additionalFields[canonical] = field.value;
        }
    }

    return event;
}

LogEntry EventNormalizer::toLogEntry(const NormalizedEvent& event) const {
    LogEntry entry;
    entry.source = event.source;
    entry.message = event.message;
    entry.severity = event.severity;
    entry.timestamp = event.timestamp;

    // Add normalized fields to metadata
    if (!event.srcIp.empty()) entry.metadata["src_ip"] = event.srcIp;
    if (!event.dstIp.empty()) entry.metadata["dst_ip"] = event.dstIp;
    if (!event.user.empty()) entry.metadata["user"] = event.user;
    if (!event.action.empty()) entry.metadata["action"] = event.action;
    if (!event.hostname.empty()) entry.metadata["hostname"] = event.hostname;
    if (!event.application.empty()) entry.metadata["application"] = event.application;
    if (!event.eventType.empty()) entry.metadata["event_type"] = event.eventType;

    for (const auto& [key, value] : event.additionalFields) {
        entry.metadata[key] = value;
    }

    return entry;
}

void EventNormalizer::addFieldMapping(const std::string& alias, const std::string& canonical) {
    std::lock_guard<std::mutex> lock(mutex_);
    fieldMappings_[alias] = canonical;
}

std::unordered_map<std::string, std::string> EventNormalizer::getFieldMappings() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return fieldMappings_;
}

std::string EventNormalizer::mapFieldName(const std::string& name) const {
    auto it = fieldMappings_.find(name);
    if (it != fieldMappings_.end()) {
        return it->second;
    }
    return name;
}

} // namespace ThreatOne::SIEM
