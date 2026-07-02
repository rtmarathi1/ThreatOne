#include <doctest/doctest.h>
#include <hids/SystemCallMonitor.h>

using namespace ThreatOne::HIDS;

TEST_CASE("SystemCallMonitor - Start and stop monitoring") {
    SystemCallMonitor monitor;

    CHECK_FALSE(monitor.isMonitoring());
    CHECK(monitor.startMonitoring());
    CHECK(monitor.isMonitoring());
    CHECK_FALSE(monitor.startMonitoring()); // already active

    CHECK(monitor.stopMonitoring());
    CHECK_FALSE(monitor.isMonitoring());
    CHECK_FALSE(monitor.stopMonitoring()); // already stopped
}

TEST_CASE("SystemCallMonitor - Record syscall events") {
    SystemCallMonitor monitor;

    SyscallEvent event;
    event.syscallName = "open";
    event.category = SyscallCategory::FileAccess;
    event.pid = 1234;
    event.processName = "test_proc";
    event.arguments = "/etc/passwd";
    event.returnCode = 0;

    monitor.recordSyscall(event);

    auto recent = monitor.getRecentEvents(10);
    REQUIRE(recent.size() == 1);
    CHECK(recent[0].syscallName == "open");
    CHECK(recent[0].pid == 1234);
}

TEST_CASE("SystemCallMonitor - Detect suspicious privilege escalation") {
    SystemCallMonitor monitor;

    SyscallEvent event;
    event.syscallName = "setuid";
    event.category = SyscallCategory::PrivilegeEscalation;
    event.pid = 5678;
    event.processName = "suspicious_proc";

    monitor.recordSyscall(event);

    auto suspicious = monitor.getSuspiciousEvents();
    REQUIRE(suspicious.size() == 1);
    CHECK(suspicious[0].suspicious);
    CHECK(suspicious[0].category == SyscallCategory::PrivilegeEscalation);
}

TEST_CASE("SystemCallMonitor - Rule-based detection") {
    SystemCallMonitor monitor;

    SyscallRule rule;
    rule.name = "Detect ptrace";
    rule.syscallPattern = "ptrace";
    rule.category = SyscallCategory::ProcessControl;
    rule.enabled = true;

    auto ruleId = monitor.addRule(rule);
    CHECK_FALSE(ruleId.empty());

    SyscallEvent event;
    event.syscallName = "ptrace";
    event.category = SyscallCategory::ProcessControl;
    event.pid = 100;

    monitor.recordSyscall(event);

    auto suspicious = monitor.getSuspiciousEvents();
    CHECK(suspicious.size() == 1);
}

TEST_CASE("SystemCallMonitor - Add rule with empty fields fails") {
    SystemCallMonitor monitor;

    SyscallRule rule;
    rule.name = "";
    rule.syscallPattern = "test";
    CHECK(monitor.addRule(rule).empty());

    rule.name = "Test";
    rule.syscallPattern = "";
    CHECK(monitor.addRule(rule).empty());
}

TEST_CASE("SystemCallMonitor - Remove and disable rules") {
    SystemCallMonitor monitor;

    SyscallRule rule;
    rule.name = "Test Rule";
    rule.syscallPattern = "write";
    rule.category = SyscallCategory::FileAccess;
    rule.enabled = true;
    auto id = monitor.addRule(rule);

    CHECK(monitor.disableRule(id));
    CHECK(monitor.enableRule(id));
    CHECK(monitor.removeRule(id));
    CHECK_FALSE(monitor.removeRule("nonexistent"));
}

TEST_CASE("SystemCallMonitor - Get events by category") {
    SystemCallMonitor monitor;

    SyscallEvent fileEvent;
    fileEvent.syscallName = "read";
    fileEvent.category = SyscallCategory::FileAccess;
    fileEvent.pid = 1;
    monitor.recordSyscall(fileEvent);

    SyscallEvent netEvent;
    netEvent.syscallName = "connect";
    netEvent.category = SyscallCategory::NetworkAccess;
    netEvent.pid = 2;
    monitor.recordSyscall(netEvent);

    auto fileEvents = monitor.getEventsByCategory(SyscallCategory::FileAccess);
    CHECK(fileEvents.size() == 1);
    CHECK(fileEvents[0].syscallName == "read");

    auto netEvents = monitor.getEventsByCategory(SyscallCategory::NetworkAccess);
    CHECK(netEvents.size() == 1);
}

TEST_CASE("SystemCallMonitor - Stats tracking") {
    SystemCallMonitor monitor;

    SyscallEvent event;
    event.syscallName = "open";
    event.category = SyscallCategory::FileAccess;
    event.pid = 1;
    monitor.recordSyscall(event);

    auto stats = monitor.getStats();
    CHECK(stats.totalEventsProcessed == 1);

    monitor.resetStats();
    stats = monitor.getStats();
    CHECK(stats.totalEventsProcessed == 0);
}

TEST_CASE("SystemCallMonitor - Get rules") {
    SystemCallMonitor monitor;

    SyscallRule rule1;
    rule1.name = "Rule1";
    rule1.syscallPattern = "open";
    rule1.enabled = true;
    monitor.addRule(rule1);

    SyscallRule rule2;
    rule2.name = "Rule2";
    rule2.syscallPattern = "write";
    rule2.enabled = true;
    monitor.addRule(rule2);

    auto rules = monitor.getRules();
    CHECK(rules.size() == 2);
}
