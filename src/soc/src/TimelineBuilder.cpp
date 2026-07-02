#include "soc/TimelineBuilder.h"
#include <mutex>

#include <algorithm>

namespace ThreatOne::SOC {

TimelineBuilder::TimelineBuilder()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("TimelineBuilder")) {
    logger_.info("TimelineBuilder initialized");
}

std::string TimelineBuilder::addEvent(const TimelineEvent& event) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = "TLE-" + std::to_string(nextEventId_++);
    TimelineEvent stored = event;
    stored.id = id;
    timelinesByEntity_[event.entityId].push_back(stored);
    allEvents_.push_back(stored);

    logger_.info("Added timeline event {} for entity {}: {}",
                 id, event.entityId, event.title);
    return id;
}

bool TimelineBuilder::removeEvent(const std::string& eventId) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Remove from allEvents
    auto it = std::find_if(allEvents_.begin(), allEvents_.end(),
        [&eventId](const TimelineEvent& e) { return e.id == eventId; });

    if (it == allEvents_.end()) {
        return false;
    }

    std::string entityId = it->entityId;
    allEvents_.erase(it);

    // Remove from entity timeline
    auto entityIt = timelinesByEntity_.find(entityId);
    if (entityIt != timelinesByEntity_.end()) {
        auto& events = entityIt->second;
        events.erase(std::remove_if(events.begin(), events.end(),
            [&eventId](const TimelineEvent& e) { return e.id == eventId; }),
            events.end());
    }

    logger_.info("Removed timeline event {}", eventId);
    return true;
}

std::vector<TimelineEvent> TimelineBuilder::getTimeline(const std::string& entityId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = timelinesByEntity_.find(entityId);
    if (it != timelinesByEntity_.end()) {
        return it->second;
    }
    return {};
}

std::vector<TimelineEvent> TimelineBuilder::getTimelineByType(
    const std::string& entityId, TimelineEventType type) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<TimelineEvent> result;
    auto it = timelinesByEntity_.find(entityId);
    if (it != timelinesByEntity_.end()) {
        for (const auto& event : it->second) {
            if (event.type == type) {
                result.push_back(event);
            }
        }
    }
    return result;
}

std::vector<TimelineEvent> TimelineBuilder::getRecentEvents(size_t count) const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (allEvents_.empty()) {
        return {};
    }

    size_t start = allEvents_.size() > count ? allEvents_.size() - count : 0;
    return std::vector<TimelineEvent>(allEvents_.begin() + static_cast<long>(start), allEvents_.end());
}

size_t TimelineBuilder::getEventCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return allEvents_.size();
}

size_t TimelineBuilder::getEventCountForEntity(const std::string& entityId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = timelinesByEntity_.find(entityId);
    if (it != timelinesByEntity_.end()) {
        return it->second.size();
    }
    return 0;
}

} // namespace ThreatOne::SOC
