#include <doctest/doctest.h>
#include <threat_intel/ThreatFeedManager.h>

#include <memory>
#include <chrono>

using namespace ThreatOne::ThreatIntel;

TEST_CASE("ThreatFeedManager - Add feed returns valid ID") {
    auto iocManager = std::make_shared<IOCManager>();
    ThreatFeedManager feedManager(iocManager);

    FeedConfig config;
    config.name = "Test Feed";
    config.url = "http://example.com/feed";
    config.format = FeedFormat::PlainText;

    auto result = feedManager.addFeed(config);
    REQUIRE(result.isOk());
    CHECK(result.value() > 0);
    CHECK(feedManager.feedCount() == 1);
}

TEST_CASE("ThreatFeedManager - Add feed with empty name fails") {
    auto iocManager = std::make_shared<IOCManager>();
    ThreatFeedManager feedManager(iocManager);

    FeedConfig config;
    config.name = "";
    config.url = "http://example.com/feed";

    auto result = feedManager.addFeed(config);
    CHECK(result.isErr());
}

TEST_CASE("ThreatFeedManager - Get feed by ID") {
    auto iocManager = std::make_shared<IOCManager>();
    ThreatFeedManager feedManager(iocManager);

    FeedConfig config;
    config.name = "Intel Feed";
    config.url = "http://intel.com/iocs";
    config.format = FeedFormat::STIX_JSON;

    auto addResult = feedManager.addFeed(config);
    REQUIRE(addResult.isOk());
    uint64_t id = addResult.value();

    auto getResult = feedManager.getFeed(id);
    REQUIRE(getResult.isOk());
    CHECK(getResult.value().name == "Intel Feed");
    CHECK(getResult.value().format == FeedFormat::STIX_JSON);
}

TEST_CASE("ThreatFeedManager - Remove feed") {
    auto iocManager = std::make_shared<IOCManager>();
    ThreatFeedManager feedManager(iocManager);

    FeedConfig config;
    config.name = "Removable Feed";
    config.url = "http://example.com";
    config.format = FeedFormat::CSV;

    auto addResult = feedManager.addFeed(config);
    REQUIRE(addResult.isOk());
    uint64_t id = addResult.value();

    CHECK(feedManager.feedCount() == 1);
    auto removeResult = feedManager.removeFeed(id);
    CHECK(removeResult.isOk());
    CHECK(feedManager.feedCount() == 0);
}

TEST_CASE("ThreatFeedManager - Remove non-existent feed fails") {
    auto iocManager = std::make_shared<IOCManager>();
    ThreatFeedManager feedManager(iocManager);

    auto result = feedManager.removeFeed(999);
    CHECK(result.isErr());
}

TEST_CASE("ThreatFeedManager - List feeds") {
    auto iocManager = std::make_shared<IOCManager>();
    ThreatFeedManager feedManager(iocManager);

    FeedConfig config1;
    config1.name = "Feed 1";
    config1.url = "http://a.com";
    config1.format = FeedFormat::PlainText;

    FeedConfig config2;
    config2.name = "Feed 2";
    config2.url = "http://b.com";
    config2.format = FeedFormat::CSV;

    feedManager.addFeed(config1);
    feedManager.addFeed(config2);

    auto feeds = feedManager.listFeeds();
    CHECK(feeds.size() == 2);
}

TEST_CASE("ThreatFeedManager - Process plain text feed data") {
    auto iocManager = std::make_shared<IOCManager>();
    ThreatFeedManager feedManager(iocManager);

    FeedConfig config;
    config.name = "PlainText Feed";
    config.url = "http://example.com/iocs.txt";
    config.format = FeedFormat::PlainText;

    auto addResult = feedManager.addFeed(config);
    REQUIRE(addResult.isOk());
    uint64_t feedId = addResult.value();

    std::string data = "192.168.1.1\n10.0.0.5\nevil.com\n";
    auto processResult = feedManager.processFeedData(feedId, data);
    REQUIRE(processResult.isOk());
    CHECK(processResult.value() == 3);
    CHECK(iocManager->size() == 3);
}

TEST_CASE("ThreatFeedManager - Process STIX JSON feed data") {
    auto iocManager = std::make_shared<IOCManager>();
    ThreatFeedManager feedManager(iocManager);

    FeedConfig config;
    config.name = "STIX Feed";
    config.url = "http://example.com/stix";
    config.format = FeedFormat::STIX_JSON;

    auto addResult = feedManager.addFeed(config);
    REQUIRE(addResult.isOk());
    uint64_t feedId = addResult.value();

    std::string data = R"({
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "pattern": "[ipv4-addr:value = '203.0.113.10']",
                "confidence": 80
            }
        ]
    })";

    auto processResult = feedManager.processFeedData(feedId, data);
    REQUIRE(processResult.isOk());
    CHECK(processResult.value() == 1);
    CHECK(iocManager->size() == 1);
}

TEST_CASE("ThreatFeedManager - Process non-existent feed fails") {
    auto iocManager = std::make_shared<IOCManager>();
    ThreatFeedManager feedManager(iocManager);

    auto result = feedManager.processFeedData(999, "some data");
    CHECK(result.isErr());
}

TEST_CASE("ThreatFeedManager - New feeds need refresh") {
    auto iocManager = std::make_shared<IOCManager>();
    ThreatFeedManager feedManager(iocManager);

    FeedConfig config;
    config.name = "Fresh Feed";
    config.url = "http://example.com";
    config.format = FeedFormat::PlainText;
    config.refreshInterval = std::chrono::seconds(3600);
    config.enabled = true;

    feedManager.addFeed(config);

    auto needsRefresh = feedManager.checkFeedRefresh();
    CHECK(needsRefresh.size() == 1);
}

TEST_CASE("ThreatFeedManager - Disabled feeds not refreshed") {
    auto iocManager = std::make_shared<IOCManager>();
    ThreatFeedManager feedManager(iocManager);

    FeedConfig config;
    config.name = "Disabled Feed";
    config.url = "http://example.com";
    config.format = FeedFormat::PlainText;
    config.enabled = false;

    feedManager.addFeed(config);

    auto needsRefresh = feedManager.checkFeedRefresh();
    CHECK(needsRefresh.empty());
}
