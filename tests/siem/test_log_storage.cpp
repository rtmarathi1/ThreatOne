#include <doctest/doctest.h>
#include <siem/LogStorage.h>
#include <string>
#include <vector>

using namespace ThreatOne::SIEM;

TEST_CASE("LogStorage - Store and retrieve entry") {
    LogStorage storage;

    LogEntry entry;
    entry.source = "firewall";
    entry.message = "Blocked connection";
    entry.severity = "medium";
    entry.timestamp = "2024-01-15T10:00:00";

    std::string id = storage.store(entry);
    CHECK_FALSE(id.empty());
    CHECK(storage.count() == 1);

    auto retrieved = storage.getById(id);
    CHECK(retrieved.source == "firewall");
    CHECK(retrieved.message == "Blocked connection");
}

TEST_CASE("LogStorage - Store batch") {
    LogStorage storage;

    std::vector<LogEntry> batch;
    for (int i = 0; i < 10; i++) {
        LogEntry entry;
        entry.source = "batch";
        entry.message = "Log " + std::to_string(i);
        batch.push_back(entry);
    }

    auto ids = storage.storeBatch(batch);
    CHECK(ids.size() == 10);
    CHECK(storage.count() == 10);
}

TEST_CASE("LogStorage - Get by source") {
    LogStorage storage;

    LogEntry e1;
    e1.source = "firewall";
    e1.message = "fw log";
    storage.store(e1);

    LogEntry e2;
    e2.source = "auth";
    e2.message = "auth log";
    storage.store(e2);

    auto fwLogs = storage.getBySource("firewall");
    CHECK(fwLogs.size() == 1);
    CHECK(fwLogs[0].source == "firewall");
}

TEST_CASE("LogStorage - Get by time range") {
    LogStorage storage;

    LogEntry e1;
    e1.source = "app";
    e1.message = "early";
    e1.timestamp = "2024-01-15T08:00:00";
    storage.store(e1);

    LogEntry e2;
    e2.source = "app";
    e2.message = "middle";
    e2.timestamp = "2024-01-15T12:00:00";
    storage.store(e2);

    LogEntry e3;
    e3.source = "app";
    e3.message = "late";
    e3.timestamp = "2024-01-15T18:00:00";
    storage.store(e3);

    auto results = storage.getByTimeRange("2024-01-15T10:00:00", "2024-01-15T14:00:00");
    REQUIRE(results.size() == 1);
    CHECK(results[0].message == "middle");
}

TEST_CASE("LogStorage - Retention policy eviction") {
    RetentionPolicy policy;
    policy.maxEntries = 5;
    policy.evictOldest = true;

    LogStorage storage(policy);

    for (int i = 0; i < 10; i++) {
        LogEntry entry;
        entry.source = "test";
        entry.message = "Entry " + std::to_string(i);
        storage.store(entry);
    }

    CHECK(storage.count() == 5);
}

TEST_CASE("LogStorage - Storage bytes estimation") {
    LogStorage storage;

    LogEntry entry;
    entry.source = "test";
    entry.message = "Hello World";
    storage.store(entry);

    CHECK(storage.getStorageBytes() > 0);
}

TEST_CASE("LogStorage - Source counts") {
    LogStorage storage;

    for (int i = 0; i < 5; i++) {
        LogEntry entry;
        entry.source = "firewall";
        entry.message = "fw " + std::to_string(i);
        storage.store(entry);
    }
    for (int i = 0; i < 3; i++) {
        LogEntry entry;
        entry.source = "auth";
        entry.message = "auth " + std::to_string(i);
        storage.store(entry);
    }

    auto counts = storage.getSourceCounts();
    CHECK(counts["firewall"] == 5);
    CHECK(counts["auth"] == 3);
}

TEST_CASE("LogStorage - Total ingested tracking") {
    LogStorage storage;

    LogEntry entry;
    entry.source = "test";
    entry.message = "test";
    storage.store(entry);
    storage.store(entry);

    CHECK(storage.getTotalIngested() == 2);
}
