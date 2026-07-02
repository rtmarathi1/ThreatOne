#include <doctest/doctest.h>
#include <soc/TimelineBuilder.h>
#include <string>

using namespace ThreatOne::SOC;

TEST_CASE("TimelineBuilder - Add event") {
    TimelineBuilder builder;

    TimelineEvent event;
    event.entityId = "CASE-1";
    event.type = TimelineEventType::CaseCreated;
    event.title = "Case created";
    event.actor = "system";

    std::string id = builder.addEvent(event);
    CHECK_FALSE(id.empty());
    CHECK(id.find("TLE-") == 0);
}

TEST_CASE("TimelineBuilder - Get timeline for entity") {
    TimelineBuilder builder;

    TimelineEvent ev1;
    ev1.entityId = "CASE-1";
    ev1.type = TimelineEventType::CaseCreated;
    ev1.title = "Created";
    builder.addEvent(ev1);

    TimelineEvent ev2;
    ev2.entityId = "CASE-1";
    ev2.type = TimelineEventType::CaseAssigned;
    ev2.title = "Assigned";
    builder.addEvent(ev2);

    TimelineEvent ev3;
    ev3.entityId = "CASE-2";
    ev3.type = TimelineEventType::CaseCreated;
    ev3.title = "Other case";
    builder.addEvent(ev3);

    auto timeline = builder.getTimeline("CASE-1");
    CHECK(timeline.size() == 2);

    auto timeline2 = builder.getTimeline("CASE-2");
    CHECK(timeline2.size() == 1);
}

TEST_CASE("TimelineBuilder - Get timeline by type") {
    TimelineBuilder builder;

    TimelineEvent ev1;
    ev1.entityId = "CASE-1";
    ev1.type = TimelineEventType::EvidenceAdded;
    ev1.title = "Evidence 1";
    builder.addEvent(ev1);

    TimelineEvent ev2;
    ev2.entityId = "CASE-1";
    ev2.type = TimelineEventType::StatusChanged;
    ev2.title = "Status change";
    builder.addEvent(ev2);

    TimelineEvent ev3;
    ev3.entityId = "CASE-1";
    ev3.type = TimelineEventType::EvidenceAdded;
    ev3.title = "Evidence 2";
    builder.addEvent(ev3);

    auto evEvents = builder.getTimelineByType(
        "CASE-1", TimelineEventType::EvidenceAdded);
    CHECK(evEvents.size() == 2);
}

TEST_CASE("TimelineBuilder - Remove event") {
    TimelineBuilder builder;

    TimelineEvent ev;
    ev.entityId = "CASE-1";
    ev.type = TimelineEventType::NoteAdded;
    ev.title = "Note";
    std::string id = builder.addEvent(ev);

    CHECK(builder.removeEvent(id));
    CHECK(builder.getEventCount() == 0);
    CHECK_FALSE(builder.removeEvent("nonexistent"));
}

TEST_CASE("TimelineBuilder - Get recent events") {
    TimelineBuilder builder;

    for (int i = 0; i < 10; i++) {
        TimelineEvent ev;
        ev.entityId = "CASE-" + std::to_string(i);
        ev.type = TimelineEventType::Custom;
        ev.title = "Event " + std::to_string(i);
        builder.addEvent(ev);
    }

    auto recent = builder.getRecentEvents(3);
    CHECK(recent.size() == 3);
}

TEST_CASE("TimelineBuilder - Event count") {
    TimelineBuilder builder;
    CHECK(builder.getEventCount() == 0);

    TimelineEvent ev;
    ev.entityId = "CASE-1";
    ev.title = "Test";
    builder.addEvent(ev);
    CHECK(builder.getEventCount() == 1);
    CHECK(builder.getEventCountForEntity("CASE-1") == 1);
    CHECK(builder.getEventCountForEntity("OTHER") == 0);
}

TEST_CASE("TimelineBuilder - Empty timeline for nonexistent entity") {
    TimelineBuilder builder;
    auto timeline = builder.getTimeline("nonexistent");
    CHECK(timeline.empty());
}
