#include <doctest/doctest.h>
#include <siem/SIEMEngine.h>

using namespace ThreatOne::SIEM;

TEST_CASE("SIEMEngine - Ingest single log") {
    SIEMEngine engine;

    LogEntry entry;
    entry.source = "firewall";
    entry.message = "Connection blocked from 10.0.0.1";
    entry.severity = "medium";
    entry.timestamp = "2024-01-15T10:00:00";

    CHECK(engine.ingestLog(entry));
}

TEST_CASE("SIEMEngine - Ingest and search logs") {
    SIEMEngine engine;

    LogEntry entry1;
    entry1.source = "firewall";
    entry1.message = "Connection blocked from 10.0.0.1";
    entry1.severity = "medium";
    entry1.timestamp = "2024-01-15T10:00:00";

    LogEntry entry2;
    entry2.source = "auth";
    entry2.message = "Login failed for user admin";
    entry2.severity = "high";
    entry2.timestamp = "2024-01-15T10:01:00";

    engine.ingestLog(entry1);
    engine.ingestLog(entry2);

    auto results = engine.searchLogs("blocked");
    CHECK(results.size() == 1);
    CHECK(results[0].source == "firewall");

    auto results2 = engine.searchLogs("admin");
    CHECK(results2.size() == 1);
    CHECK(results2[0].source == "auth");
}

TEST_CASE("SIEMEngine - Batch ingestion") {
    SIEMEngine engine;

    std::vector<LogEntry> batch;
    for (int i = 0; i < 10; i++) {
        LogEntry entry;
        entry.source = "batch_source";
        entry.message = "Batch log entry " + std::to_string(i);
        entry.severity = "low";
        entry.timestamp = "2024-01-15T10:0" + std::to_string(i) + ":00";
        batch.push_back(entry);
    }

    CHECK(engine.ingestBatch(batch));

    auto results = engine.searchLogs("Batch log");
    CHECK(results.size() == 10);
}

TEST_CASE("SIEMEngine - Parse syslog format") {
    SIEMEngine engine;

    std::string syslog = "Jan 15 10:30:45 webserver nginx[1234]: GET /index.html 200";
    auto fields = engine.parseLog(syslog, LogFormat::Syslog);

    REQUIRE_FALSE(fields.empty());

    bool hasTimestamp = false;
    bool hasHostname = false;
    bool hasApp = false;
    bool hasMessage = false;

    for (const auto& f : fields) {
        if (f.name == "timestamp") { hasTimestamp = true; CHECK(f.type == "timestamp"); }
        if (f.name == "hostname") { hasHostname = true; CHECK(f.value == "webserver"); }
        if (f.name == "application") { hasApp = true; CHECK(f.value == "nginx"); }
        if (f.name == "message") { hasMessage = true; }
    }

    CHECK(hasTimestamp);
    CHECK(hasHostname);
    CHECK(hasApp);
    CHECK(hasMessage);
}

TEST_CASE("SIEMEngine - Parse JSON format") {
    SIEMEngine engine;

    std::string jsonLog = R"({"event": "login", "user": "admin", "status": "failed", "attempts": 5})";
    auto fields = engine.parseLog(jsonLog, LogFormat::JSON);

    REQUIRE_FALSE(fields.empty());

    bool hasEvent = false;
    bool hasUser = false;
    bool hasAttempts = false;

    for (const auto& f : fields) {
        if (f.name == "event") { hasEvent = true; CHECK(f.value == "login"); }
        if (f.name == "user") { hasUser = true; CHECK(f.value == "admin"); }
        if (f.name == "attempts") { hasAttempts = true; CHECK(f.value == "5"); }
    }

    CHECK(hasEvent);
    CHECK(hasUser);
    CHECK(hasAttempts);
}

TEST_CASE("SIEMEngine - Parse CEF format") {
    SIEMEngine engine;

    std::string cefLog = "CEF:0|Security|IDS|1.0|100|Intrusion Detected|8|src=10.0.0.1 dst=192.168.1.1";
    auto fields = engine.parseLog(cefLog, LogFormat::CEF);

    REQUIRE_FALSE(fields.empty());

    bool hasVersion = false;
    bool hasVendor = false;
    bool hasSeverity = false;
    bool hasSrc = false;

    for (const auto& f : fields) {
        if (f.name == "version") { hasVersion = true; CHECK(f.value == "0"); }
        if (f.name == "device_vendor") { hasVendor = true; CHECK(f.value == "Security"); }
        if (f.name == "severity") { hasSeverity = true; CHECK(f.value == "8"); }
        if (f.name == "src") { hasSrc = true; CHECK(f.value == "10.0.0.1"); }
    }

    CHECK(hasVersion);
    CHECK(hasVendor);
    CHECK(hasSeverity);
    CHECK(hasSrc);
}

TEST_CASE("SIEMEngine - Create and retrieve alert") {
    SIEMEngine engine;

    SIEMAlert alert;
    alert.title = "Brute force detected";
    alert.severity = "high";
    alert.description = "Multiple login failures";
    alert.ruleId = "RULE-001";

    std::string id = engine.createAlert(alert);
    CHECK_FALSE(id.empty());

    auto alerts = engine.getAlerts();
    REQUIRE(alerts.size() == 1);
    CHECK(alerts[0].title == "Brute force detected");
    CHECK(alerts[0].severity == "high");
}

TEST_CASE("SIEMEngine - Create and retrieve rule") {
    SIEMEngine engine;

    SIEMRule rule;
    rule.name = "Failed login detection";
    rule.condition = "event_type=login_failed";
    rule.severity = "high";
    rule.enabled = true;

    std::string id = engine.createRule(rule);
    CHECK_FALSE(id.empty());

    auto rules = engine.getRules();
    REQUIRE(rules.size() == 1);
    CHECK(rules[0].name == "Failed login detection");
}

TEST_CASE("SIEMEngine - Correlation rule triggers alert when threshold breached") {
    SIEMEngine engine;

    CorrelationRule rule;
    rule.name = "Brute force rule";
    rule.condition = "event_type=login_failed";
    rule.timeWindowSeconds = 600;
    rule.threshold = 3;
    rule.severity = "high";
    rule.enabled = true;

    engine.createCorrelationRule(rule);

    // Ingest logs that match the condition
    for (int i = 0; i < 5; i++) {
        LogEntry entry;
        entry.source = "auth_server";
        entry.message = "Login attempt failed";
        entry.severity = "medium";
        entry.timestamp = "2024-01-15T10:0" + std::to_string(i) + ":00";
        entry.metadata["event_type"] = "login_failed";
        engine.ingestLog(entry);
    }

    auto alerts = engine.evaluateRules();
    REQUIRE_FALSE(alerts.empty());
    CHECK(alerts[0].severity == "high");
    CHECK(alerts[0].title.find("Brute force rule") != std::string::npos);
    CHECK(alerts[0].matchedLogIds.size() >= 3);
}

TEST_CASE("SIEMEngine - Correlation rule does not fire below threshold") {
    SIEMEngine engine;

    CorrelationRule rule;
    rule.name = "High threshold rule";
    rule.condition = "event_type=login_failed";
    rule.timeWindowSeconds = 600;
    rule.threshold = 10;
    rule.severity = "critical";
    rule.enabled = true;

    engine.createCorrelationRule(rule);

    // Ingest only 3 matching logs (below threshold of 10)
    for (int i = 0; i < 3; i++) {
        LogEntry entry;
        entry.source = "auth";
        entry.message = "Failed login";
        entry.severity = "medium";
        entry.metadata["event_type"] = "login_failed";
        engine.ingestLog(entry);
    }

    auto alerts = engine.evaluateRules();
    CHECK(alerts.empty());
}

TEST_CASE("SIEMEngine - Disabled correlation rule does not fire") {
    SIEMEngine engine;

    CorrelationRule rule;
    rule.name = "Disabled rule";
    rule.condition = "source=malware";
    rule.timeWindowSeconds = 300;
    rule.threshold = 1;
    rule.severity = "critical";
    rule.enabled = false;

    engine.createCorrelationRule(rule);

    LogEntry entry;
    entry.source = "malware";
    entry.message = "Malware detected";
    entry.severity = "critical";
    engine.ingestLog(entry);

    auto alerts = engine.evaluateRules();
    CHECK(alerts.empty());
}

TEST_CASE("SIEMEngine - Search with text filter") {
    SIEMEngine engine;

    LogEntry entry1;
    entry1.source = "webserver";
    entry1.message = "GET /api/users 200";
    entry1.severity = "low";
    entry1.timestamp = "2024-01-15T10:00:00";
    engine.ingestLog(entry1);

    LogEntry entry2;
    entry2.source = "webserver";
    entry2.message = "POST /api/login 401";
    entry2.severity = "medium";
    entry2.timestamp = "2024-01-15T10:01:00";
    engine.ingestLog(entry2);

    SearchQuery query;
    query.text = "login";

    auto results = engine.search(query);
    REQUIRE(results.size() == 1);
    CHECK(results[0].message.find("login") != std::string::npos);
}

TEST_CASE("SIEMEngine - Search with field filter") {
    SIEMEngine engine;

    LogEntry entry1;
    entry1.source = "firewall";
    entry1.message = "Blocked connection";
    entry1.severity = "medium";
    engine.ingestLog(entry1);

    LogEntry entry2;
    entry2.source = "auth";
    entry2.message = "Login successful";
    entry2.severity = "low";
    engine.ingestLog(entry2);

    SearchQuery query;
    query.fields["source"] = "firewall";

    auto results = engine.search(query);
    REQUIRE(results.size() == 1);
    CHECK(results[0].source == "firewall");
}

TEST_CASE("SIEMEngine - Search with time range") {
    SIEMEngine engine;

    LogEntry entry1;
    entry1.source = "app";
    entry1.message = "Event A";
    entry1.timestamp = "2024-01-15T08:00:00";
    engine.ingestLog(entry1);

    LogEntry entry2;
    entry2.source = "app";
    entry2.message = "Event B";
    entry2.timestamp = "2024-01-15T12:00:00";
    engine.ingestLog(entry2);

    LogEntry entry3;
    entry3.source = "app";
    entry3.message = "Event C";
    entry3.timestamp = "2024-01-15T18:00:00";
    engine.ingestLog(entry3);

    SearchQuery query;
    query.timeStart = "2024-01-15T10:00:00";
    query.timeEnd = "2024-01-15T14:00:00";

    auto results = engine.search(query);
    REQUIRE(results.size() == 1);
    CHECK(results[0].message == "Event B");
}

TEST_CASE("SIEMEngine - Search with limit") {
    SIEMEngine engine;

    for (int i = 0; i < 20; i++) {
        LogEntry entry;
        entry.source = "bulk";
        entry.message = "Log message " + std::to_string(i);
        entry.severity = "low";
        engine.ingestLog(entry);
    }

    SearchQuery query;
    query.text = "Log message";
    query.limit = 5;

    auto results = engine.search(query);
    CHECK(results.size() == 5);
}

TEST_CASE("SIEMEngine - Dashboard metrics reflect ingested data") {
    SIEMEngine engine;

    for (int i = 0; i < 10; i++) {
        LogEntry entry;
        entry.source = (i < 6) ? "firewall" : "auth";
        entry.message = "Test log " + std::to_string(i);
        entry.severity = "low";
        engine.ingestLog(entry);
    }

    auto metrics = engine.getDashboardMetrics();
    CHECK(metrics.totalLogs == 10);
    CHECK(metrics.storageUsedBytes > 0);
    CHECK_FALSE(metrics.topSources.empty());

    // Firewall should be the top source (6 logs)
    CHECK(metrics.topSources[0].first == "firewall");
    CHECK(metrics.topSources[0].second == 6);
}

TEST_CASE("SIEMEngine - Dashboard metrics with no data") {
    SIEMEngine engine;

    auto metrics = engine.getDashboardMetrics();
    CHECK(metrics.totalLogs == 0);
    CHECK(metrics.topSources.empty());
    CHECK(metrics.storageUsedBytes == 0);
}

TEST_CASE("SIEMEngine - Search with metadata field filter") {
    SIEMEngine engine;

    LogEntry entry1;
    entry1.source = "auth";
    entry1.message = "Login from user1";
    entry1.severity = "low";
    entry1.metadata["user"] = "user1";
    engine.ingestLog(entry1);

    LogEntry entry2;
    entry2.source = "auth";
    entry2.message = "Login from user2";
    entry2.severity = "low";
    entry2.metadata["user"] = "user2";
    engine.ingestLog(entry2);

    SearchQuery query;
    query.fields["user"] = "user1";

    auto results = engine.search(query);
    REQUIRE(results.size() == 1);
    CHECK(results[0].metadata.at("user") == "user1");
}
