#include <doctest/doctest.h>
#include <updates/UpdateManager.h>

using namespace ThreatOne::Updates;

TEST_CASE("UpdateScheduler - Create policy") {
    UpdateManager mgr;
    auto& us = mgr.getUpdateScheduler();

    SchedulePolicy policy;
    policy.name = "Daily Check";
    policy.type = ScheduleType::Daily;
    policy.preferredHour = 3;

    auto id = us.createPolicy(policy);
    CHECK_FALSE(id.empty());

    auto retrieved = us.getPolicy(id);
    REQUIRE(retrieved.has_value());
    CHECK(retrieved->name == "Daily Check");
    CHECK(retrieved->type == ScheduleType::Daily);
}

TEST_CASE("UpdateScheduler - Active policy") {
    UpdateManager mgr;
    auto& us = mgr.getUpdateScheduler();

    SchedulePolicy policy;
    policy.name = "Test";
    auto id = us.createPolicy(policy);

    auto active = us.getActivePolicy();
    REQUIRE(active.has_value());
    CHECK(active->id == id);
}

TEST_CASE("UpdateScheduler - Schedule and execute task") {
    UpdateManager mgr;
    auto& us = mgr.getUpdateScheduler();

    auto taskId = us.scheduleCheck("2024-01-01T03:00:00Z");
    CHECK_FALSE(taskId.empty());
    CHECK(us.getPendingTaskCount() == 1);

    CHECK(us.executeTask(taskId));
    CHECK(us.getPendingTaskCount() == 0);

    auto completed = us.getCompletedTasks();
    CHECK(completed.size() == 1);
}

TEST_CASE("UpdateScheduler - Cancel task") {
    UpdateManager mgr;
    auto& us = mgr.getUpdateScheduler();

    auto taskId = us.scheduleCheck("2024-01-01T03:00:00Z");
    CHECK(us.cancelScheduledTask(taskId));
    CHECK(us.getPendingTaskCount() == 0);
}

TEST_CASE("UpdateScheduler - Schedule installation") {
    UpdateManager mgr;
    auto& us = mgr.getUpdateScheduler();

    auto taskId = us.scheduleInstallation("2.0.0", "2024-01-02T02:00:00Z");
    CHECK_FALSE(taskId.empty());

    auto pending = us.getPendingTasks();
    CHECK(pending.size() == 1);
}

TEST_CASE("UpdateScheduler - Delete policy") {
    UpdateManager mgr;
    auto& us = mgr.getUpdateScheduler();

    SchedulePolicy policy;
    policy.name = "Temp";
    auto id = us.createPolicy(policy);

    CHECK(us.deletePolicy(id));
    CHECK_FALSE(us.getPolicy(id).has_value());
}

TEST_CASE("UpdateScheduler - Statistics") {
    UpdateManager mgr;
    auto& us = mgr.getUpdateScheduler();

    us.scheduleCheck("t1");
    us.scheduleCheck("t2");

    CHECK(us.getTotalTasksScheduled() == 2);
}
