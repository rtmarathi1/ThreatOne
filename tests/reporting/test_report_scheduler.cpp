#include <doctest/doctest.h>
#include <reporting/ReportScheduler.h>

#include <chrono>

using namespace ThreatOne::Reporting;

TEST_CASE("ReportScheduler - create schedule") {
    ReportScheduler scheduler;

    ReportSchedule sched;
    sched.reportConfigId = "config-001";
    sched.frequency = ScheduleFrequency::Daily;
    sched.enabled = true;
    sched.distributionList = {"admin@example.com"};
    sched.retentionDays = 30;

    auto result = scheduler.createSchedule(sched);
    REQUIRE(result.isOk());
    CHECK_FALSE(result.value().empty());
    CHECK(scheduler.getScheduleCount() == 1);
}

TEST_CASE("ReportScheduler - empty config ID returns error") {
    ReportScheduler scheduler;

    ReportSchedule sched;
    sched.reportConfigId = "";

    auto result = scheduler.createSchedule(sched);
    REQUIRE(result.isErr());
    CHECK(result.error().category() == ThreatOne::Core::ErrorCategory::Validation);
}

TEST_CASE("ReportScheduler - cancel schedule") {
    ReportScheduler scheduler;

    ReportSchedule sched;
    sched.reportConfigId = "config-001";
    auto result = scheduler.createSchedule(sched);
    REQUIRE(result.isOk());

    CHECK(scheduler.cancelSchedule(result.value()));
    CHECK(scheduler.getScheduleCount() == 0);
    CHECK_FALSE(scheduler.cancelSchedule("nonexistent"));
}

TEST_CASE("ReportScheduler - enable and disable") {
    ReportScheduler scheduler;

    ReportSchedule sched;
    sched.reportConfigId = "config-001";
    sched.enabled = true;
    auto result = scheduler.createSchedule(sched);
    REQUIRE(result.isOk());
    std::string id = result.value();

    CHECK(scheduler.enableSchedule(id, false));
    auto retrieved = scheduler.getSchedule(id);
    REQUIRE(retrieved.has_value());
    CHECK_FALSE(retrieved->enabled);

    CHECK(scheduler.enableSchedule(id, true));
    retrieved = scheduler.getSchedule(id);
    CHECK(retrieved->enabled);

    CHECK_FALSE(scheduler.enableSchedule("nonexistent", true));
}

TEST_CASE("ReportScheduler - frequency check") {
    ReportScheduler scheduler;

    SUBCASE("Daily schedule with past next-run is due") {
        ReportSchedule sched;
        sched.reportConfigId = "config-daily";
        sched.frequency = ScheduleFrequency::Daily;
        sched.enabled = true;
        // Set nextRun in the past
        sched.nextRun = std::chrono::system_clock::now() - std::chrono::hours(1);
        auto result = scheduler.createSchedule(sched);
        REQUIRE(result.isOk());

        CHECK(scheduler.isScheduleDue(result.value()));
    }

    SUBCASE("Weekly schedule with future next-run is not due") {
        ReportSchedule sched;
        sched.reportConfigId = "config-weekly";
        sched.frequency = ScheduleFrequency::Weekly;
        sched.enabled = true;
        // Set nextRun in the future
        sched.nextRun = std::chrono::system_clock::now() + std::chrono::hours(100);
        auto result = scheduler.createSchedule(sched);
        REQUIRE(result.isOk());

        CHECK_FALSE(scheduler.isScheduleDue(result.value()));
    }

    SUBCASE("Disabled schedule is never due") {
        ReportSchedule sched;
        sched.reportConfigId = "config-disabled";
        sched.frequency = ScheduleFrequency::Monthly;
        sched.enabled = false;
        sched.nextRun = std::chrono::system_clock::now() - std::chrono::hours(1);
        auto result = scheduler.createSchedule(sched);
        REQUIRE(result.isOk());

        CHECK_FALSE(scheduler.isScheduleDue(result.value()));
    }
}

TEST_CASE("ReportScheduler - get due schedules") {
    ReportScheduler scheduler;

    ReportSchedule sched1;
    sched1.reportConfigId = "config-1";
    sched1.enabled = true;
    sched1.nextRun = std::chrono::system_clock::now() - std::chrono::hours(1);
    scheduler.createSchedule(sched1);

    ReportSchedule sched2;
    sched2.reportConfigId = "config-2";
    sched2.enabled = true;
    sched2.nextRun = std::chrono::system_clock::now() + std::chrono::hours(100);
    scheduler.createSchedule(sched2);

    auto due = scheduler.getDueSchedules();
    CHECK(due.size() == 1);
}

TEST_CASE("ReportScheduler - mark as run updates timing") {
    ReportScheduler scheduler;

    ReportSchedule sched;
    sched.reportConfigId = "config-run";
    sched.frequency = ScheduleFrequency::Daily;
    sched.enabled = true;
    sched.nextRun = std::chrono::system_clock::now() - std::chrono::hours(1);
    auto result = scheduler.createSchedule(sched);
    REQUIRE(result.isOk());
    std::string id = result.value();

    CHECK(scheduler.isScheduleDue(id));
    CHECK(scheduler.markAsRun(id));

    // After marking as run, next run should be in the future
    CHECK_FALSE(scheduler.isScheduleDue(id));

    auto retrieved = scheduler.getSchedule(id);
    REQUIRE(retrieved.has_value());
    CHECK(retrieved->lastRun > std::chrono::system_clock::time_point{});
    CHECK(retrieved->nextRun > std::chrono::system_clock::now());
}

TEST_CASE("ReportScheduler - distribution list management") {
    ReportScheduler scheduler;

    ReportSchedule sched;
    sched.reportConfigId = "config-dist";
    auto result = scheduler.createSchedule(sched);
    REQUIRE(result.isOk());
    std::string id = result.value();

    CHECK(scheduler.addRecipient(id, "alice@example.com"));
    CHECK(scheduler.addRecipient(id, "bob@example.com"));

    // Adding duplicate should not create second entry
    CHECK(scheduler.addRecipient(id, "alice@example.com"));

    auto recipients = scheduler.getRecipients(id);
    CHECK(recipients.size() == 2);

    CHECK(scheduler.removeRecipient(id, "alice@example.com"));
    recipients = scheduler.getRecipients(id);
    CHECK(recipients.size() == 1);
    CHECK(recipients[0] == "bob@example.com");

    // Remove nonexistent recipient
    CHECK_FALSE(scheduler.removeRecipient(id, "charlie@example.com"));

    // Operations on nonexistent schedule
    CHECK_FALSE(scheduler.addRecipient("no-id", "x@y.com"));
    CHECK_FALSE(scheduler.removeRecipient("no-id", "x@y.com"));
    CHECK(scheduler.getRecipients("no-id").empty());
}

TEST_CASE("ReportScheduler - retention policy") {
    ReportScheduler scheduler;

    ReportSchedule sched;
    sched.reportConfigId = "config-ret";
    sched.retentionDays = 90;
    auto result = scheduler.createSchedule(sched);
    REQUIRE(result.isOk());
    std::string id = result.value();

    CHECK(scheduler.getRetentionDays(id) == 90);
    CHECK(scheduler.setRetentionDays(id, 30));
    CHECK(scheduler.getRetentionDays(id) == 30);

    // Invalid retention
    CHECK_FALSE(scheduler.setRetentionDays(id, 0));
    CHECK_FALSE(scheduler.setRetentionDays(id, -1));

    // Nonexistent schedule
    CHECK(scheduler.getRetentionDays("no-id") == -1);
    CHECK_FALSE(scheduler.setRetentionDays("no-id", 30));
}
