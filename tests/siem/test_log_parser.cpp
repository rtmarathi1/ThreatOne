#include <doctest/doctest.h>
#include <siem/LogParser.h>
#include <string>

using namespace ThreatOne::SIEM;

TEST_CASE("LogParser - Parse syslog format") {
    LogParser parser;

    std::string syslog = "Jan 15 10:30:45 webserver nginx[1234]: GET /index.html 200";
    auto fields = parser.parseSyslog(syslog);

    REQUIRE_FALSE(fields.empty());

    bool hasTimestamp = false;
    bool hasHostname = false;
    for (const auto& f : fields) {
        if (f.name == "timestamp") hasTimestamp = true;
        if (f.name == "hostname" && f.value == "webserver") hasHostname = true;
    }
    CHECK(hasTimestamp);
    CHECK(hasHostname);
}

TEST_CASE("LogParser - Parse JSON format") {
    LogParser parser;

    std::string jsonLog = R"({"event": "login", "user": "admin", "status": "failed"})";
    auto fields = parser.parseJSON(jsonLog);

    REQUIRE_FALSE(fields.empty());

    bool hasEvent = false;
    bool hasUser = false;
    for (const auto& f : fields) {
        if (f.name == "event" && f.value == "login") hasEvent = true;
        if (f.name == "user" && f.value == "admin") hasUser = true;
    }
    CHECK(hasEvent);
    CHECK(hasUser);
}

TEST_CASE("LogParser - Parse CEF format") {
    LogParser parser;

    std::string cef = "CEF:0|Security|IDS|1.0|100|Intrusion|8|src=10.0.0.1 dst=192.168.1.1";
    auto fields = parser.parseCEF(cef);

    REQUIRE_FALSE(fields.empty());

    bool hasVersion = false;
    bool hasSrc = false;
    for (const auto& f : fields) {
        if (f.name == "version" && f.value == "0") hasVersion = true;
        if (f.name == "src" && f.value == "10.0.0.1") hasSrc = true;
    }
    CHECK(hasVersion);
    CHECK(hasSrc);
}

TEST_CASE("LogParser - Parse LEEF format") {
    LogParser parser;

    std::string leef = "LEEF:1.0|Microsoft|MSExchange|4.0|1234|src=10.0.0.1";
    auto fields = parser.parseLEEF(leef);

    REQUIRE_FALSE(fields.empty());

    bool hasVendor = false;
    for (const auto& f : fields) {
        if (f.name == "vendor" && f.value == "Microsoft") hasVendor = true;
    }
    CHECK(hasVendor);
}

TEST_CASE("LogParser - Parse Windows Event Log format") {
    LogParser parser;

    std::string winLog = "EventID=4625 Source=Security Level=Warning";
    auto fields = parser.parseWindowsEventLog(winLog);

    REQUIRE_FALSE(fields.empty());

    bool hasEventId = false;
    for (const auto& f : fields) {
        if (f.name == "EventID") hasEventId = true;
    }
    CHECK(hasEventId);
}

TEST_CASE("LogParser - Detect format automatically") {
    LogParser parser;

    CHECK(parser.detectFormat("CEF:0|Vendor|Product|1.0|1|Name|5|ext=val") == LogFormat::CEF);
    CHECK(parser.detectFormat("LEEF:1.0|Vendor|Product|1.0|1|key=val") == LogFormat::LEEF);
    CHECK(parser.detectFormat(R"({"event": "test"})") == LogFormat::JSON);
    CHECK(parser.detectFormat("Jan 15 10:30:45 host app: msg") == LogFormat::Syslog);
}

TEST_CASE("LogParser - Generic parse dispatch") {
    LogParser parser;

    auto fields = parser.parse("CEF:0|Sec|IDS|1|100|Alert|7|src=1.2.3.4", LogFormat::CEF);
    REQUIRE_FALSE(fields.empty());

    bool hasSrc = false;
    for (const auto& f : fields) {
        if (f.name == "src") hasSrc = true;
    }
    CHECK(hasSrc);
}
