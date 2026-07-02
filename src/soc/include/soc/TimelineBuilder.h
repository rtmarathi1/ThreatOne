#pragma once
#include <unordered_map>

#include "soc/ISOCManager.h"
#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>

namespace ThreatOne::SOC {

enum class TimelineEventType {
    CaseCreated,
    CaseAssigned,
    CaseEscalated,
    StatusChanged,
    EvidenceAdded,
    PlaybookExecuted,
    NoteAdded,
    AlertTriggered,
    Custom
};

struct TimelineEvent {
    std::string id;
    std::string entityId;  // case ID or incident ID
    TimelineEventType type = TimelineEventType::Custom;
    std::string title;
    std::string description;
    std::string timestamp;
    std::string actor;  // who performed the action
    std::unordered_map<std::string, std::string> metadata;
};

class TimelineBuilder {
public:
    TimelineBuilder();
    ~TimelineBuilder() = default;

    // Event recording
    std::string addEvent(const TimelineEvent& event);
    bool removeEvent(const std::string& eventId);

    // Timeline queries
    [[nodiscard]] std::vector<TimelineEvent> getTimeline(const std::string& entityId) const;
    [[nodiscard]] std::vector<TimelineEvent> getTimelineByType(
        const std::string& entityId, TimelineEventType type) const;
    [[nodiscard]] std::vector<TimelineEvent> getRecentEvents(size_t count) const;

    // Statistics
    [[nodiscard]] size_t getEventCount() const;
    [[nodiscard]] size_t getEventCountForEntity(const std::string& entityId) const;

private:
    mutable std::mutex mutex_;
    std::map<std::string, std::vector<TimelineEvent>> timelinesByEntity_;
    std::vector<TimelineEvent> allEvents_;
    int nextEventId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::SOC
