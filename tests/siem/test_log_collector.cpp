#include <doctest/doctest.h>
#include <siem/LogCollector.h>
#include <string>
#include <vector>

using namespace ThreatOne::SIEM;

TEST_CASE("LogCollector - Add and remove sources") {
    LogCollector collector;

    LogSource source;
    source.name = "Firewall Logs";
    source.type = "syslog";
    source.endpoint = "192.168.1.1:514";

    std::string id = collector.addSource(source);
    CHECK_FALSE(id.empty());

    auto sources = collector.getSources();
    REQUIRE(sources.size() == 1);
    CHECK(sources[0].name == "Firewall Logs");
    CHECK(sources[0].type == "syslog");

    CHECK(collector.removeSource(id));
    CHECK(collector.getSources().empty());
}

TEST_CASE("LogCollector - Start and stop collection") {
    LogCollector collector;

    CHECK_FALSE(collector.isCollecting());
    collector.startCollection();
    CHECK(collector.isCollecting());
    collector.stopCollection();
    CHECK_FALSE(collector.isCollecting());
}

TEST_CASE("LogCollector - Collect single entry into buffer") {
    LogCollector collector;

    LogEntry entry;
    entry.source = "firewall";
    entry.message = "Connection blocked";
    entry.severity = "medium";

    CHECK(collector.collect(entry));
    CHECK(collector.getBufferSize() == 1);

    auto buffer = collector.getBuffer();
    REQUIRE(buffer.size() == 1);
    CHECK(buffer[0].source == "firewall");
}

TEST_CASE("LogCollector - Collect batch") {
    LogCollector collector;

    std::vector<LogEntry> batch;
    for (int i = 0; i < 5; i++) {
        LogEntry entry;
        entry.source = "batch_src";
        entry.message = "Message " + std::to_string(i);
        batch.push_back(entry);
    }

    CHECK(collector.collectBatch(batch));
    CHECK(collector.getBufferSize() == 5);
    CHECK(collector.getTotalCollected() == 5);
}

TEST_CASE("LogCollector - Clear buffer") {
    LogCollector collector;

    LogEntry entry;
    entry.source = "test";
    entry.message = "Test log";
    collector.collect(entry);

    CHECK(collector.getBufferSize() == 1);
    collector.clearBuffer();
    CHECK(collector.getBufferSize() == 0);
}

TEST_CASE("LogCollector - Callback on collection") {
    LogCollector collector;

    int callbackCount = 0;
    collector.onLogCollected([&callbackCount](const LogEntry&) {
        callbackCount++;
    });

    LogEntry entry;
    entry.source = "test";
    entry.message = "Callback test";
    collector.collect(entry);

    CHECK(callbackCount == 1);
}
