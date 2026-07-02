#include <doctest/doctest.h>
#include <siem/SearchEngine.h>
#include <siem/LogStorage.h>
#include <memory>
#include <string>

using namespace ThreatOne::SIEM;

TEST_CASE("SearchEngine - Text search") {
    auto storage = std::make_shared<LogStorage>();

    LogEntry e1;
    e1.source = "firewall";
    e1.message = "Connection blocked from 10.0.0.1";
    storage->store(e1);

    LogEntry e2;
    e2.source = "auth";
    e2.message = "Login successful for admin";
    storage->store(e2);

    SearchEngine engine(storage);

    auto results = engine.textSearch("blocked");
    REQUIRE(results.size() == 1);
    CHECK(results[0].source == "firewall");
}

TEST_CASE("SearchEngine - Search with field filter") {
    auto storage = std::make_shared<LogStorage>();

    LogEntry e1;
    e1.source = "firewall";
    e1.message = "Log from fw";
    storage->store(e1);

    LogEntry e2;
    e2.source = "auth";
    e2.message = "Log from auth";
    storage->store(e2);

    SearchEngine engine(storage);

    SearchQuery query;
    query.fields["source"] = "auth";

    auto results = engine.search(query);
    REQUIRE(results.size() == 1);
    CHECK(results[0].source == "auth");
}

TEST_CASE("SearchEngine - Search with time range") {
    auto storage = std::make_shared<LogStorage>();

    LogEntry e1;
    e1.source = "app";
    e1.message = "Early event";
    e1.timestamp = "2024-01-15T08:00:00";
    storage->store(e1);

    LogEntry e2;
    e2.source = "app";
    e2.message = "Middle event";
    e2.timestamp = "2024-01-15T12:00:00";
    storage->store(e2);

    SearchEngine engine(storage);

    SearchQuery query;
    query.timeStart = "2024-01-15T10:00:00";
    query.timeEnd = "2024-01-15T14:00:00";

    auto results = engine.search(query);
    REQUIRE(results.size() == 1);
    CHECK(results[0].message == "Middle event");
}

TEST_CASE("SearchEngine - Search with limit") {
    auto storage = std::make_shared<LogStorage>();

    for (int i = 0; i < 20; i++) {
        LogEntry entry;
        entry.source = "bulk";
        entry.message = "Entry " + std::to_string(i);
        storage->store(entry);
    }

    SearchEngine engine(storage);

    SearchQuery query;
    query.limit = 5;

    auto results = engine.search(query);
    CHECK(results.size() == 5);
}

TEST_CASE("SearchEngine - Count matching entries") {
    auto storage = std::make_shared<LogStorage>();

    for (int i = 0; i < 10; i++) {
        LogEntry entry;
        entry.source = (i < 6) ? "firewall" : "auth";
        entry.message = "msg " + std::to_string(i);
        storage->store(entry);
    }

    SearchEngine engine(storage);

    SearchQuery query;
    query.fields["source"] = "firewall";

    auto count = engine.count(query);
    CHECK(count == 6);
}

TEST_CASE("SearchEngine - Aggregate by field") {
    auto storage = std::make_shared<LogStorage>();

    for (int i = 0; i < 5; i++) {
        LogEntry entry;
        entry.source = "firewall";
        entry.message = "fw " + std::to_string(i);
        storage->store(entry);
    }
    for (int i = 0; i < 3; i++) {
        LogEntry entry;
        entry.source = "auth";
        entry.message = "auth " + std::to_string(i);
        storage->store(entry);
    }

    SearchEngine engine(storage);

    auto agg = engine.aggregate("source");
    CHECK(agg.fieldName == "source");
    CHECK(agg.buckets["firewall"] == 5);
    CHECK(agg.buckets["auth"] == 3);
}

TEST_CASE("SearchEngine - Search with metadata filter") {
    auto storage = std::make_shared<LogStorage>();

    LogEntry e1;
    e1.source = "auth";
    e1.message = "login";
    e1.metadata["user"] = "admin";
    storage->store(e1);

    LogEntry e2;
    e2.source = "auth";
    e2.message = "login";
    e2.metadata["user"] = "guest";
    storage->store(e2);

    SearchEngine engine(storage);

    SearchQuery query;
    query.fields["user"] = "admin";

    auto results = engine.search(query);
    REQUIRE(results.size() == 1);
    CHECK(results[0].metadata.at("user") == "admin");
}
