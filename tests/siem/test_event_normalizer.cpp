#include <doctest/doctest.h>
#include <siem/EventNormalizer.h>
#include <string>
#include <vector>

using namespace ThreatOne::SIEM;

TEST_CASE("EventNormalizer - Normalize parsed fields") {
    EventNormalizer normalizer;

    std::vector<ParsedField> fields = {
        {"timestamp", "2024-01-15T10:00:00", "timestamp"},
        {"hostname", "webserver", "string"},
        {"message", "GET /api/users 200", "string"},
        {"src", "10.0.0.1", "string"},
        {"dst", "192.168.1.1", "string"}
    };

    auto event = normalizer.normalize(fields, "webserver", "low");
    CHECK(event.timestamp == "2024-01-15T10:00:00");
    CHECK(event.hostname == "webserver");
    CHECK(event.message == "GET /api/users 200");
    CHECK(event.srcIp == "10.0.0.1");
    CHECK(event.dstIp == "192.168.1.1");
    CHECK(event.source == "webserver");
    CHECK(event.severity == "low");
}

TEST_CASE("EventNormalizer - Field alias mapping") {
    EventNormalizer normalizer;

    std::vector<ParsedField> fields = {
        {"username", "admin", "string"},
        {"source_ip", "172.16.0.5", "string"},
        {"activity", "login", "string"}
    };

    auto event = normalizer.normalize(fields);
    CHECK(event.user == "admin");
    CHECK(event.srcIp == "172.16.0.5");
    CHECK(event.action == "login");
}

TEST_CASE("EventNormalizer - Convert back to LogEntry") {
    EventNormalizer normalizer;

    NormalizedEvent event;
    event.timestamp = "2024-01-15T10:00:00";
    event.source = "firewall";
    event.severity = "high";
    event.message = "Connection blocked";
    event.srcIp = "10.0.0.1";
    event.user = "admin";

    auto entry = normalizer.toLogEntry(event);
    CHECK(entry.source == "firewall");
    CHECK(entry.severity == "high");
    CHECK(entry.message == "Connection blocked");
    CHECK(entry.timestamp == "2024-01-15T10:00:00");
    CHECK(entry.metadata["src_ip"] == "10.0.0.1");
    CHECK(entry.metadata["user"] == "admin");
}

TEST_CASE("EventNormalizer - Custom field mapping") {
    EventNormalizer normalizer;

    normalizer.addFieldMapping("client_addr", "src_ip");

    std::vector<ParsedField> fields = {
        {"client_addr", "192.168.1.100", "string"}
    };

    auto event = normalizer.normalize(fields);
    CHECK(event.srcIp == "192.168.1.100");
}

TEST_CASE("EventNormalizer - Get field mappings") {
    EventNormalizer normalizer;

    auto mappings = normalizer.getFieldMappings();
    CHECK_FALSE(mappings.empty());
    CHECK(mappings["src"] == "src_ip");
    CHECK(mappings["username"] == "user");
}
