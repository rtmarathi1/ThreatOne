#include "network/ConnectionLogger.h"

#include <algorithm>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace ThreatOne::Network {

ConnectionLogger::ConnectionLogger()
    : logger_(Core::Logger::instance().getModuleLogger("ConnectionLogger")) {
    logger_.info("ConnectionLogger initialized (capacity: {})", maxCapacity_);
}

ConnectionLogger::ConnectionLogger(size_t maxCapacity)
    : maxCapacity_(maxCapacity)
    , logger_(Core::Logger::instance().getModuleLogger("ConnectionLogger")) {
    events_.reserve(std::min(maxCapacity, size_t(1000)));
    logger_.info("ConnectionLogger initialized (capacity: {})", maxCapacity_);
}

void ConnectionLogger::logEvent(const ConnectionEvent& event) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (events_.size() < maxCapacity_) {
        events_.push_back(event);
    } else {
        // Ring buffer: overwrite oldest entry
        events_[writePos_] = event;
        wrapped_ = true;
    }
    writePos_ = (writePos_ + 1) % maxCapacity_;

    logger_.trace("Logged connection event: {}:{} -> {}:{} ({})",
                  event.sourceIP, event.sourcePort,
                  event.destIP, event.destPort, event.action);
}

std::vector<ConnectionEvent> ConnectionLogger::getEvents(const TimeRange& range) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ConnectionEvent> result;

    for (const auto& event : events_) {
        if (event.timestamp >= range.start && event.timestamp <= range.end) {
            result.push_back(event);
        }
    }

    return result;
}

std::vector<ConnectionEvent> ConnectionLogger::getEventsByIP(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ConnectionEvent> result;

    for (const auto& event : events_) {
        if (event.sourceIP == ip || event.destIP == ip) {
            result.push_back(event);
        }
    }

    return result;
}

std::vector<ConnectionEvent> ConnectionLogger::getAllEvents() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return events_;
}

size_t ConnectionLogger::getEventCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return events_.size();
}

void ConnectionLogger::setMaxCapacity(size_t capacity) {
    std::lock_guard<std::mutex> lock(mutex_);
    maxCapacity_ = capacity;
    // If current events exceed new capacity, trim from the beginning
    if (events_.size() > maxCapacity_) {
        events_.erase(events_.begin(),
                      events_.begin() + static_cast<long>(events_.size() - maxCapacity_));
        writePos_ = 0;
        wrapped_ = false;
    }
    logger_.info("Max capacity set to {}", capacity);
}

void ConnectionLogger::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    events_.clear();
    writePos_ = 0;
    wrapped_ = false;
    logger_.info("Connection log cleared");
}

std::vector<ConnectionEvent> ConnectionLogger::flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ConnectionEvent> flushed = std::move(events_);
    events_.clear();
    writePos_ = 0;
    wrapped_ = false;
    logger_.info("Flushed {} events", flushed.size());
    return flushed;
}

} // namespace ThreatOne::Network
