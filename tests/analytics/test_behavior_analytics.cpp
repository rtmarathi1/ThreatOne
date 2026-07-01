#include <doctest/doctest.h>
#include <analytics/BehaviorAnalyticsEngine.h>

#include <string>
#include <vector>
#include <chrono>

using namespace ThreatOne::Analytics;

TEST_CASE("BehaviorAnalyticsEngine - baseline building") {
    BehaviorAnalyticsEngine engine;

    SUBCASE("Build baseline from events") {
        std::vector<UserEvent> events;
        auto baseTime = std::chrono::system_clock::now();

        for (int i = 0; i < 20; ++i) {
            UserEvent event;
            event.userId = "user1";
            event.eventType = (i % 2 == 0) ? "file_access" : "login";
            event.resource = "/data/reports";
            // Simulate events during work hours (9-17)
            event.timestamp = baseTime + std::chrono::hours(i % 8 + 9);
            events.push_back(event);
        }

        engine.buildBaseline("user1", events);
        CHECK(engine.hasBaseline("user1") == true);

        auto baseline = engine.getBaseline("user1");
        CHECK(baseline.eventCount == 20);
        CHECK(baseline.averageEventRate > 0.0);
        CHECK(!baseline.typicalAccessPatterns.empty());
        CHECK(!baseline.commonProcesses.empty());
    }

    SUBCASE("Empty events does not create baseline") {
        std::vector<UserEvent> events;
        engine.buildBaseline("empty_user", events);
        CHECK(engine.hasBaseline("empty_user") == false);
    }
}

TEST_CASE("BehaviorAnalyticsEngine - multiple user baselines") {
    BehaviorAnalyticsEngine engine;
    auto baseTime = std::chrono::system_clock::now();

    std::vector<UserEvent> events1;
    for (int i = 0; i < 10; ++i) {
        UserEvent event;
        event.userId = "userA";
        event.eventType = "login";
        event.resource = "/home/userA";
        event.timestamp = baseTime + std::chrono::hours(i);
        events1.push_back(event);
    }

    std::vector<UserEvent> events2;
    for (int i = 0; i < 10; ++i) {
        UserEvent event;
        event.userId = "userB";
        event.eventType = "file_write";
        event.resource = "/data/shared";
        event.timestamp = baseTime + std::chrono::hours(i);
        events2.push_back(event);
    }

    engine.buildBaseline("userA", events1);
    engine.buildBaseline("userB", events2);

    CHECK(engine.hasBaseline("userA") == true);
    CHECK(engine.hasBaseline("userB") == true);
    CHECK(engine.getUserCount() == 2);
}

TEST_CASE("BehaviorAnalyticsEngine - deviation detection") {
    BehaviorAnalyticsEngine engine;

    // Use a fixed base time at midnight UTC
    auto baseTime = std::chrono::system_clock::from_time_t(0) + std::chrono::hours(24 * 1000);

    std::vector<UserEvent> events;
    for (int i = 0; i < 30; ++i) {
        UserEvent event;
        event.userId = "worker";
        event.eventType = "file_access";
        event.resource = "/projects/normal";
        // Events during hours 9-12 (mean around 10.5)
        event.timestamp = baseTime + std::chrono::hours(9 + (i % 4));
        events.push_back(event);
    }
    engine.buildBaseline("worker", events);

    SUBCASE("Normal time event not flagged") {
        UserEvent normalEvent;
        normalEvent.userId = "worker";
        normalEvent.eventType = "file_access";
        normalEvent.resource = "/projects/normal";
        // Set timestamp to hour 10 (within baseline)
        normalEvent.timestamp = baseTime + std::chrono::hours(10);

        auto result = engine.detectDeviation("worker", normalEvent);
        // Event at normal time and normal resource should not be deviation
        CHECK(result.isDeviation == false);
    }

    SUBCASE("No baseline returns no deviation") {
        UserEvent event;
        event.userId = "unknown_user";
        event.eventType = "file_access";
        event.resource = "/etc/shadow";

        auto result = engine.detectDeviation("unknown_user", event);
        CHECK(result.isDeviation == false);
        CHECK(result.description.find("No baseline") != std::string::npos);
    }
}

TEST_CASE("BehaviorAnalyticsEngine - time-of-day analysis") {
    BehaviorAnalyticsEngine engine;

    // Use a fixed base time at midnight UTC so hours are predictable
    // Epoch (Jan 1 1970 00:00 UTC) + some full days so we start at midnight
    auto baseTime = std::chrono::system_clock::from_time_t(0) + std::chrono::hours(24 * 1000);

    // Build baseline with events only during hours 9-12
    std::vector<UserEvent> events;
    for (int i = 0; i < 30; ++i) {
        UserEvent event;
        event.userId = "daytime_user";
        event.eventType = "login";
        event.resource = "/app";
        event.timestamp = baseTime + std::chrono::hours(9 + (i % 4));
        events.push_back(event);
    }
    engine.buildBaseline("daytime_user", events);

    SUBCASE("Late night activity flagged as deviation") {
        // 3 AM is far from the 9-12 baseline (mean ~10.5, stddev ~1)
        auto lateNight = baseTime + std::chrono::hours(3);
        auto result = engine.analyzeTimeOfDay("daytime_user", lateNight);
        CHECK(result.isDeviation == true);
        CHECK(result.deviationScore > 0.0);
        CHECK(result.baselineMetric == "time_of_day");
    }

    SUBCASE("Normal working hour not flagged") {
        auto workTime = baseTime + std::chrono::hours(10);
        auto result = engine.analyzeTimeOfDay("daytime_user", workTime);
        CHECK(result.isDeviation == false);
    }

    SUBCASE("No baseline for unknown user") {
        auto someTime = baseTime + std::chrono::hours(14);
        auto result = engine.analyzeTimeOfDay("no_such_user", someTime);
        CHECK(result.isDeviation == false);
    }
}

TEST_CASE("BehaviorAnalyticsEngine - access pattern analysis") {
    BehaviorAnalyticsEngine engine;

    // Build baseline with known resource patterns
    auto baseTime = std::chrono::system_clock::from_time_t(0) + std::chrono::hours(24 * 1000);
    std::vector<UserEvent> events;
    for (int i = 0; i < 20; ++i) {
        UserEvent event;
        event.userId = "access_user";
        event.eventType = "read";
        event.resource = (i % 2 == 0) ? "/data/reports" : "/data/dashboard";
        event.timestamp = baseTime + std::chrono::hours(i);
        events.push_back(event);
    }
    engine.buildBaseline("access_user", events);

    SUBCASE("Known resource not flagged") {
        auto result = engine.analyzeAccessPattern("access_user", "/data/reports");
        CHECK(result.isDeviation == false);
    }

    SUBCASE("Unknown resource flagged as deviation") {
        auto result = engine.analyzeAccessPattern("access_user", "/etc/shadow");
        CHECK(result.isDeviation == true);
        CHECK(result.deviationScore > 0.0);
    }

    SUBCASE("No baseline returns no deviation") {
        auto result = engine.analyzeAccessPattern("unknown", "/some/path");
        CHECK(result.isDeviation == false);
    }
}

TEST_CASE("BehaviorAnalyticsEngine - update baseline") {
    BehaviorAnalyticsEngine engine;

    auto baseTime = std::chrono::system_clock::from_time_t(0) + std::chrono::hours(24 * 1000);
    std::vector<UserEvent> events;
    for (int i = 0; i < 10; ++i) {
        UserEvent event;
        event.userId = "update_user";
        event.eventType = "login";
        event.resource = "/app";
        event.timestamp = baseTime + std::chrono::hours(i);
        events.push_back(event);
    }
    engine.buildBaseline("update_user", events);

    SUBCASE("Update increments event count") {
        auto before = engine.getBaseline("update_user");

        UserEvent newEvent;
        newEvent.userId = "update_user";
        newEvent.eventType = "login";
        newEvent.resource = "/app";
        newEvent.timestamp = baseTime + std::chrono::hours(11);
        engine.updateBaseline("update_user", newEvent);

        auto after = engine.getBaseline("update_user");
        CHECK(after.eventCount > before.eventCount);
    }
}
