#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <chrono>
#include <mutex>

#include "core/Logger.h"

namespace ThreatOne::Network {

struct ConnectionEvent {
    std::chrono::system_clock::time_point timestamp;
    std::string sourceIP;
    std::string destIP;
    uint16_t sourcePort = 0;
    uint16_t destPort = 0;
    std::string protocol;
    std::string action; // "allowed" or "denied"
    std::string ruleId;
    std::string applicationPath;
    uint64_t bytesTransferred = 0;
};

struct TimeRange {
    std::chrono::system_clock::time_point start;
    std::chrono::system_clock::time_point end;
};

class ConnectionLogger {
public:
    ConnectionLogger();
    explicit ConnectionLogger(size_t maxCapacity);

    void logEvent(const ConnectionEvent& event);
    std::vector<ConnectionEvent> getEvents(const TimeRange& range) const;
    std::vector<ConnectionEvent> getEventsByIP(const std::string& ip) const;
    std::vector<ConnectionEvent> getAllEvents() const;
    size_t getEventCount() const;
    void setMaxCapacity(size_t capacity);
    void clear();

    // Flush to database (stub - returns events that would be flushed)
    std::vector<ConnectionEvent> flush();

private:
    mutable std::mutex mutex_;
    std::vector<ConnectionEvent> events_;
    size_t maxCapacity_ = 10000;
    size_t writePos_ = 0;
    bool wrapped_ = false;
    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Network
