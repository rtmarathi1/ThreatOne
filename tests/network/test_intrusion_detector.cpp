#include <doctest/doctest.h>
#include <network/IntrusionDetector.h>

using namespace ThreatOne::Network;

TEST_CASE("IntrusionDetector - initial state") {
    IntrusionDetector detector;
    CHECK(detector.getRules().empty());
    CHECK(detector.getAlertCount() == 0);
    CHECK(detector.getAlerts().empty());
}

TEST_CASE("IntrusionDetector - add and remove rules") {
    IntrusionDetector detector;

    IDSRule rule;
    rule.id = "rule1";
    rule.name = "Test Rule";
    rule.protocol = "TCP";
    rule.action = IDSAction::Alert;
    detector.addRule(rule);

    auto rules = detector.getRules();
    REQUIRE(rules.size() == 1);
    CHECK(rules[0].id == "rule1");

    detector.removeRule("rule1");
    CHECK(detector.getRules().empty());
}

TEST_CASE("IntrusionDetector - port scan detection") {
    IntrusionDetector detector;

    // Simulate a port scan: many ports from same source
    std::vector<uint16_t> ports;
    for (uint16_t i = 1; i <= 20; i++) {
        ports.push_back(i);
    }

    bool detected = detector.detectPortScan("192.168.1.100", ports);
    CHECK(detected);
}

TEST_CASE("IntrusionDetector - normal traffic does not trigger port scan") {
    IntrusionDetector detector;

    // Only a few ports - not a scan
    std::vector<uint16_t> ports = {80, 443};
    bool detected = detector.detectPortScan("192.168.1.100", ports);
    CHECK_FALSE(detected);
}

TEST_CASE("IntrusionDetector - SYN flood detection") {
    IntrusionDetector detector;

    // Each call adds one timestamp entry; need >= count to trigger
    // Call many times to exceed threshold
    for (int i = 0; i < 100; i++) {
        detector.detectSYNFlood("10.0.0.1", 100, 10);
    }
    // The 100th call should have triggered it
    bool detected = detector.detectSYNFlood("10.0.0.1", 100, 10);
    CHECK(detected);
}

TEST_CASE("IntrusionDetector - low count SYN does not trigger flood") {
    IntrusionDetector detector;

    // Only call once - 1 < 100 so should not trigger
    bool detected = detector.detectSYNFlood("10.0.0.1", 100, 60);
    CHECK_FALSE(detected);
}

TEST_CASE("IntrusionDetector - brute force detection") {
    IntrusionDetector detector;

    // Each call adds one timestamp; need >= failCount to trigger
    for (int i = 0; i < 49; i++) {
        detector.detectBruteForce("10.0.0.1", 22, 50, 60);
    }
    // The 50th call should trigger (size == 50 >= 50)
    bool detected = detector.detectBruteForce("10.0.0.1", 22, 50, 60);
    CHECK(detected);
}

TEST_CASE("IntrusionDetector - low count does not trigger brute force") {
    IntrusionDetector detector;

    // Only one call - 1 < 50
    bool detected = detector.detectBruteForce("10.0.0.1", 22, 50, 60);
    CHECK_FALSE(detected);
}

TEST_CASE("IntrusionDetector - rule-based content matching") {
    IntrusionDetector detector;

    IDSRule rule;
    rule.id = "sql_injection";
    rule.name = "SQL Injection Attempt";
    rule.protocol = "TCP";
    rule.contentPattern = "UNION SELECT";
    rule.action = IDSAction::Drop;
    rule.destPort = 80;
    detector.addRule(rule);

    PacketInfo packet;
    packet.sourceIP = "10.0.0.5";
    packet.destIP = "10.0.0.1";
    packet.sourcePort = 5000;
    packet.destPort = 80;
    packet.protocol = "TCP";
    packet.payload = "GET /page?id=1 UNION SELECT * FROM users";

    auto alerts = detector.evaluate(packet);
    CHECK(!alerts.empty());
    if (!alerts.empty()) {
        CHECK(alerts[0].ruleId == "sql_injection");
        CHECK(alerts[0].action == IDSAction::Drop);
    }
}

TEST_CASE("IntrusionDetector - normal traffic does not trigger rule alerts") {
    IntrusionDetector detector;

    IDSRule rule;
    rule.id = "sql_injection";
    rule.name = "SQL Injection Attempt";
    rule.protocol = "TCP";
    rule.contentPattern = "SELECT.*FROM";
    rule.action = IDSAction::Drop;
    rule.destPort = 80;
    detector.addRule(rule);

    PacketInfo packet;
    packet.sourceIP = "10.0.0.5";
    packet.destIP = "10.0.0.1";
    packet.sourcePort = 5000;
    packet.destPort = 80;
    packet.protocol = "TCP";
    packet.payload = "GET /index.html HTTP/1.1";

    auto alerts = detector.evaluate(packet);
    CHECK(alerts.empty());
}

TEST_CASE("IntrusionDetector - clear alerts") {
    IntrusionDetector detector;

    IDSRule rule;
    rule.id = "test_rule";
    rule.name = "Test";
    rule.protocol = "TCP";
    rule.contentPattern = "attack";
    rule.action = IDSAction::Alert;
    detector.addRule(rule);

    PacketInfo packet;
    packet.sourceIP = "1.2.3.4";
    packet.destIP = "5.6.7.8";
    packet.protocol = "TCP";
    packet.payload = "this is an attack payload";
    detector.evaluate(packet);

    CHECK(detector.getAlertCount() > 0);
    detector.clearAlerts();
    CHECK(detector.getAlertCount() == 0);
}

TEST_CASE("IntrusionDetector - alerts include source/dest info") {
    IntrusionDetector detector;

    IDSRule rule;
    rule.id = "xss_rule";
    rule.name = "XSS Attempt";
    rule.protocol = "TCP";
    rule.contentPattern = "<script>";
    rule.action = IDSAction::Alert;
    detector.addRule(rule);

    PacketInfo packet;
    packet.sourceIP = "192.168.1.10";
    packet.destIP = "10.0.0.1";
    packet.sourcePort = 4444;
    packet.destPort = 8080;
    packet.protocol = "TCP";
    packet.payload = "<script>alert('xss')</script>";

    auto alerts = detector.evaluate(packet);
    REQUIRE(!alerts.empty());
    CHECK(alerts[0].sourceIP == "192.168.1.10");
    CHECK(alerts[0].destIP == "10.0.0.1");
}

TEST_CASE("IntrusionDetector - alert eviction at capacity") {
    IntrusionDetector detector;

    // Add a rule that matches any TCP packet with "trigger" in the payload
    IDSRule rule;
    rule.id = "eviction_rule";
    rule.name = "Eviction Test Rule";
    rule.protocol = "TCP";
    rule.contentPattern = "trigger";
    rule.action = IDSAction::Alert;
    detector.addRule(rule);

    // Push more alerts than kMaxAlerts to trigger eviction.
    // Each evaluate() call with a matching packet generates one alert.
    const size_t totalAlerts = IntrusionDetector::kMaxAlerts + 100;
    for (size_t i = 0; i < totalAlerts; i++) {
        PacketInfo packet;
        packet.sourceIP = "10.0.0." + std::to_string(i % 256);
        packet.destIP = "192.168.1.1";
        packet.sourcePort = static_cast<uint16_t>(1000 + (i % 60000));
        packet.destPort = 80;
        packet.protocol = "TCP";
        packet.payload = "trigger_" + std::to_string(i);

        detector.evaluate(packet);
    }

    // Alert count should be capped at kMaxAlerts
    CHECK(detector.getAlertCount() == IntrusionDetector::kMaxAlerts);

    // Verify oldest alerts were evicted: the first 100 alerts (indices 0-99)
    // should have been evicted. The remaining alerts should correspond to
    // packets sent with i >= 100. The oldest remaining alert should have
    // source IP corresponding to i=100: "10.0.0.100"
    auto alerts = detector.getAlerts();
    REQUIRE(alerts.size() == IntrusionDetector::kMaxAlerts);

    // The first (oldest) alert in the collection should be from index 100
    CHECK(alerts[0].sourceIP == "10.0.0.100");
    // The payload description should reference the rule
    CHECK(alerts[0].ruleName == "Eviction Test Rule");

    // The last (newest) alert should be from the final iteration
    size_t lastIdx = totalAlerts - 1;
    CHECK(alerts.back().sourceIP == "10.0.0." + std::to_string(lastIdx % 256));
}
