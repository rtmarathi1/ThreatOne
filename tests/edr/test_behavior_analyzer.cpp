#include <doctest/doctest.h>
#include <edr/BehaviorAnalyzer.h>

#include <chrono>

using namespace ThreatOne::EDR;

TEST_CASE("BehaviorAnalyzer - default window size") {
    BehaviorAnalyzer analyzer(100);
    CHECK(analyzer.getWindowSize() == 100);
    CHECK(analyzer.getEventCount() == 0);
}

TEST_CASE("BehaviorAnalyzer - events are added and counted") {
    BehaviorAnalyzer analyzer(100);
    EDREvent event;
    event.type = "file_write";
    event.source = "test";
    analyzer.addEvent(event);
    CHECK(analyzer.getEventCount() == 1);
}

TEST_CASE("BehaviorAnalyzer - window size limits event count") {
    BehaviorAnalyzer analyzer(5);
    for (int i = 0; i < 10; i++) {
        EDREvent event;
        event.type = "file_write";
        event.source = "test_" + std::to_string(i);
        analyzer.addEvent(event);
    }
    CHECK(analyzer.getEventCount() == 5);
}

TEST_CASE("BehaviorAnalyzer - clear removes all events") {
    BehaviorAnalyzer analyzer(100);
    EDREvent event;
    event.type = "test";
    analyzer.addEvent(event);
    analyzer.clear();
    CHECK(analyzer.getEventCount() == 0);
}

TEST_CASE("BehaviorAnalyzer - detect ransomware pattern with renames and high entropy") {
    BehaviorAnalyzer analyzer(1000);
    auto now = std::chrono::steady_clock::now();

    // Simulate many file renames to .encrypted extension
    for (int i = 0; i < 10; i++) {
        EDREvent event;
        event.type = "file_rename";
        event.source = "malware.exe";
        event.path = "/home/user/document_" + std::to_string(i) + ".encrypted";
        event.timestamp = now + std::chrono::milliseconds(i * 100);
        analyzer.addEvent(event);
    }

    // Add high entropy writes
    for (int i = 0; i < 5; i++) {
        EDREvent event;
        event.type = "file_write";
        event.source = "malware.exe";
        event.path = "/home/user/data_" + std::to_string(i) + ".encrypted";
        event.entropy = 7.9;
        event.timestamp = now + std::chrono::milliseconds(1000 + i * 100);
        analyzer.addEvent(event);
    }

    auto alerts = analyzer.detectRansomwareBehavior();
    REQUIRE(!alerts.empty());
    CHECK(alerts[0].patternType == "ransomware");
    CHECK(alerts[0].severity == "critical");
}

TEST_CASE("BehaviorAnalyzer - normal file operations do not trigger ransomware") {
    BehaviorAnalyzer analyzer(1000);
    auto now = std::chrono::steady_clock::now();

    // Normal file operations - no renames, low entropy
    for (int i = 0; i < 5; i++) {
        EDREvent event;
        event.type = "file_write";
        event.source = "editor";
        event.path = "/home/user/document_" + std::to_string(i) + ".txt";
        event.entropy = 3.5; // Normal text entropy
        event.timestamp = now + std::chrono::milliseconds(i * 1000);
        analyzer.addEvent(event);
    }

    auto alerts = analyzer.detectRansomwareBehavior();
    CHECK(alerts.empty());
}

TEST_CASE("BehaviorAnalyzer - renames to crypto extensions gives high severity") {
    BehaviorAnalyzer analyzer(1000);
    auto now = std::chrono::steady_clock::now();

    for (int i = 0; i < 8; i++) {
        EDREvent event;
        event.type = "file_rename";
        event.source = "suspect";
        event.path = "/home/user/file_" + std::to_string(i) + ".locky";
        event.timestamp = now + std::chrono::milliseconds(i * 100);
        analyzer.addEvent(event);
    }

    auto alerts = analyzer.detectRansomwareBehavior();
    REQUIRE(!alerts.empty());
    CHECK(alerts[0].severity == "high");
}

TEST_CASE("BehaviorAnalyzer - detect privilege escalation") {
    BehaviorAnalyzer analyzer(1000);
    auto now = std::chrono::steady_clock::now();

    EDREvent event1;
    event1.type = "process_exec";
    event1.source = "httpd";
    event1.details = "sudo /bin/bash";
    event1.timestamp = now;
    analyzer.addEvent(event1);

    EDREvent event2;
    event2.type = "process_exec";
    event2.source = "httpd";
    event2.details = "sudo cat /etc/shadow";
    event2.timestamp = now + std::chrono::seconds(1);
    analyzer.addEvent(event2);

    EDREvent event3;
    event3.type = "suid_change";
    event3.source = "httpd";
    event3.path = "/tmp/backdoor";
    event3.timestamp = now + std::chrono::seconds(2);
    analyzer.addEvent(event3);

    EDREvent event4;
    event4.type = "suid_change";
    event4.source = "httpd";
    event4.path = "/tmp/rootshell";
    event4.timestamp = now + std::chrono::seconds(3);
    analyzer.addEvent(event4);

    auto alerts = analyzer.detectPrivilegeEscalation();
    REQUIRE(!alerts.empty());
    CHECK(alerts[0].patternType == "privilege_escalation");
    CHECK(alerts[0].severity == "high");
}

TEST_CASE("BehaviorAnalyzer - normal sudo does not trigger privilege escalation") {
    BehaviorAnalyzer analyzer(1000);
    auto now = std::chrono::steady_clock::now();

    EDREvent event;
    event.type = "process_exec";
    event.source = "bash";
    event.details = "sudo apt-get update";
    event.timestamp = now;
    analyzer.addEvent(event);

    auto alerts = analyzer.detectPrivilegeEscalation();
    CHECK(alerts.empty());
}

TEST_CASE("BehaviorAnalyzer - detect data exfiltration") {
    BehaviorAnalyzer analyzer(1000);
    auto now = std::chrono::steady_clock::now();

    // Archive creation
    EDREvent archiveEvent;
    archiveEvent.type = "file_write";
    archiveEvent.source = "tar";
    archiveEvent.path = "/tmp/data_dump.tar.gz";
    archiveEvent.timestamp = now;
    analyzer.addEvent(archiveEvent);

    // Large outbound transfers
    for (int i = 0; i < 5; i++) {
        EDREvent netEvent;
        netEvent.type = "network_out";
        netEvent.source = "curl";
        netEvent.path = "evil.com:443";
        netEvent.dataSize = 30 * 1024 * 1024; // 30MB each = 150MB total
        netEvent.timestamp = now + std::chrono::seconds(i + 1);
        analyzer.addEvent(netEvent);
    }

    auto alerts = analyzer.detectDataExfiltration();
    REQUIRE(!alerts.empty());
    CHECK(alerts[0].patternType == "data_exfiltration");
    CHECK(alerts[0].severity == "high");
}

TEST_CASE("BehaviorAnalyzer - normal network does not trigger exfiltration") {
    BehaviorAnalyzer analyzer(1000);
    auto now = std::chrono::steady_clock::now();

    for (int i = 0; i < 5; i++) {
        EDREvent netEvent;
        netEvent.type = "network_out";
        netEvent.source = "browser";
        netEvent.path = "google.com:443";
        netEvent.dataSize = 1024; // 1KB each
        netEvent.timestamp = now + std::chrono::seconds(i);
        analyzer.addEvent(netEvent);
    }

    auto alerts = analyzer.detectDataExfiltration();
    CHECK(alerts.empty());
}

TEST_CASE("BehaviorAnalyzer - analyzePatterns returns all detected patterns") {
    BehaviorAnalyzer analyzer(1000);
    auto now = std::chrono::steady_clock::now();

    // Add ransomware-like events
    for (int i = 0; i < 10; i++) {
        EDREvent event;
        event.type = "file_rename";
        event.source = "malware";
        event.path = "/data/file_" + std::to_string(i) + ".encrypted";
        event.timestamp = now + std::chrono::milliseconds(i * 50);
        analyzer.addEvent(event);
    }

    for (int i = 0; i < 5; i++) {
        EDREvent event;
        event.type = "file_write";
        event.source = "malware";
        event.path = "/data/enc_" + std::to_string(i) + ".encrypted";
        event.entropy = 7.8;
        event.timestamp = now + std::chrono::milliseconds(500 + i * 50);
        analyzer.addEvent(event);
    }

    auto alerts = analyzer.analyzePatterns();
    CHECK(!alerts.empty());

    bool foundRansomware = false;
    for (const auto& alert : alerts) {
        if (alert.patternType == "ransomware") foundRansomware = true;
    }
    CHECK(foundRansomware);
}
