#include <doctest/doctest.h>
#include <monitor/ServiceWatcher.h>

using namespace ThreatOne::Monitor;

TEST_CASE("ServiceWatcher - Add service") {
    ServiceWatcher watcher;

    ServiceInfo svc;
    svc.name = "nginx";
    svc.displayName = "Nginx Web Server";
    svc.status = ServiceStatus::Running;
    svc.pid = 1234;

    auto id = watcher.addService(svc);
    CHECK_FALSE(id.empty());

    auto services = watcher.getServices();
    REQUIRE(services.size() == 1);
    CHECK(services[0].name == "nginx");
}

TEST_CASE("ServiceWatcher - Add service empty name fails") {
    ServiceWatcher watcher;
    ServiceInfo svc;
    svc.name = "";
    CHECK(watcher.addService(svc).empty());
}

TEST_CASE("ServiceWatcher - Remove service") {
    ServiceWatcher watcher;
    ServiceInfo svc;
    svc.name = "test";
    auto id = watcher.addService(svc);

    CHECK(watcher.removeService(id));
    CHECK_FALSE(watcher.removeService("nonexistent"));
    CHECK(watcher.getServices().empty());
}

TEST_CASE("ServiceWatcher - Update service status") {
    ServiceWatcher watcher;

    ServiceInfo svc;
    svc.name = "apache";
    svc.status = ServiceStatus::Running;
    auto id = watcher.addService(svc);

    CHECK(watcher.updateServiceStatus(id, ServiceStatus::Stopped, "Manual stop"));
    auto info = watcher.getService(id);
    CHECK(info.status == ServiceStatus::Stopped);
    CHECK_FALSE(watcher.updateServiceStatus("invalid", ServiceStatus::Running));
}

TEST_CASE("ServiceWatcher - Status change generates event") {
    ServiceWatcher watcher;

    ServiceInfo svc;
    svc.name = "mysql";
    svc.status = ServiceStatus::Running;
    auto id = watcher.addService(svc);

    watcher.updateServiceStatus(id, ServiceStatus::Failed, "Crash");

    auto events = watcher.getEvents();
    REQUIRE(events.size() == 1);
    CHECK(events[0].serviceName == "mysql");
    CHECK(events[0].previousStatus == ServiceStatus::Running);
    CHECK(events[0].newStatus == ServiceStatus::Failed);
    CHECK(events[0].reason == "Crash");
}

TEST_CASE("ServiceWatcher - Restart increments counter") {
    ServiceWatcher watcher;

    ServiceInfo svc;
    svc.name = "worker";
    svc.status = ServiceStatus::Stopped;
    auto id = watcher.addService(svc);

    watcher.updateServiceStatus(id, ServiceStatus::Running, "Start");
    watcher.updateServiceStatus(id, ServiceStatus::Stopped, "Stop");
    watcher.updateServiceStatus(id, ServiceStatus::Running, "Restart");

    CHECK(watcher.getRestartCount(id) == 2);
}

TEST_CASE("ServiceWatcher - Get running services") {
    ServiceWatcher watcher;

    ServiceInfo running;
    running.name = "running_svc";
    running.status = ServiceStatus::Running;
    watcher.addService(running);

    ServiceInfo stopped;
    stopped.name = "stopped_svc";
    stopped.status = ServiceStatus::Stopped;
    watcher.addService(stopped);

    auto runningList = watcher.getRunningServices();
    CHECK(runningList.size() == 1);
    CHECK(runningList[0].name == "running_svc");
}

TEST_CASE("ServiceWatcher - Get failed services") {
    ServiceWatcher watcher;

    ServiceInfo svc;
    svc.name = "failed_svc";
    svc.status = ServiceStatus::Failed;
    watcher.addService(svc);

    auto failed = watcher.getFailedServices();
    CHECK(failed.size() == 1);
}

TEST_CASE("ServiceWatcher - Get events for specific service") {
    ServiceWatcher watcher;

    ServiceInfo svc1;
    svc1.name = "svc1";
    svc1.status = ServiceStatus::Running;
    auto id1 = watcher.addService(svc1);

    ServiceInfo svc2;
    svc2.name = "svc2";
    svc2.status = ServiceStatus::Running;
    auto id2 = watcher.addService(svc2);

    watcher.updateServiceStatus(id1, ServiceStatus::Stopped);
    watcher.updateServiceStatus(id2, ServiceStatus::Stopped);
    watcher.updateServiceStatus(id1, ServiceStatus::Running);

    auto events1 = watcher.getEventsForService(id1);
    CHECK(events1.size() == 2);
    auto events2 = watcher.getEventsForService(id2);
    CHECK(events2.size() == 1);
}

TEST_CASE("ServiceWatcher - Recent events") {
    ServiceWatcher watcher;

    ServiceInfo svc;
    svc.name = "svc";
    svc.status = ServiceStatus::Running;
    auto id = watcher.addService(svc);

    for (int i = 0; i < 5; ++i) {
        watcher.updateServiceStatus(id, ServiceStatus::Stopped);
        watcher.updateServiceStatus(id, ServiceStatus::Running);
    }

    auto recent = watcher.getRecentEvents(3);
    CHECK(recent.size() == 3);
}

TEST_CASE("ServiceWatcher - Stats") {
    ServiceWatcher watcher;

    ServiceInfo running;
    running.name = "running";
    running.status = ServiceStatus::Running;
    watcher.addService(running);

    ServiceInfo stopped;
    stopped.name = "stopped";
    stopped.status = ServiceStatus::Stopped;
    watcher.addService(stopped);

    ServiceInfo failed;
    failed.name = "failed";
    failed.status = ServiceStatus::Failed;
    watcher.addService(failed);

    auto stats = watcher.getStats();
    CHECK(stats.totalServices == 3);
    CHECK(stats.runningServices == 1);
    CHECK(stats.stoppedServices == 1);
    CHECK(stats.failedServices == 1);
}
