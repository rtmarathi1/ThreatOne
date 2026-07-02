#include <doctest/doctest.h>
#include <threat_intel/IOCManager.h>

#include <thread>
#include <vector>
#include <chrono>
#include <cstdint>

using namespace ThreatOne::ThreatIntel;

TEST_CASE("IOCManager - Add IOC returns valid ID") {
    IOCManager manager;
    IOC ioc;
    ioc.type = IOCType::IP;
    ioc.value = "192.168.1.100";
    ioc.source = "test";
    ioc.confidence = 0.8;

    auto result = manager.addIOC(ioc);
    REQUIRE(result.isOk());
    CHECK(result.value() > 0);
    CHECK(manager.size() == 1);
}

TEST_CASE("IOCManager - Add IOC with empty value fails") {
    IOCManager manager;
    IOC ioc;
    ioc.type = IOCType::IP;
    ioc.value = "";

    auto result = manager.addIOC(ioc);
    CHECK(result.isErr());
}

TEST_CASE("IOCManager - Get IOC by ID") {
    IOCManager manager;
    IOC ioc;
    ioc.type = IOCType::Domain;
    ioc.value = "malicious.com";
    ioc.source = "feed1";
    ioc.confidence = 0.9;

    auto addResult = manager.addIOC(ioc);
    REQUIRE(addResult.isOk());
    uint64_t id = addResult.value();

    auto getResult = manager.getIOCById(id);
    REQUIRE(getResult.isOk());
    CHECK(getResult.value().value == "malicious.com");
    CHECK(getResult.value().type == IOCType::Domain);
    CHECK(getResult.value().confidence == doctest::Approx(0.9));
}

TEST_CASE("IOCManager - Get non-existent IOC fails") {
    IOCManager manager;
    auto result = manager.getIOCById(999);
    CHECK(result.isErr());
}

TEST_CASE("IOCManager - Remove IOC") {
    IOCManager manager;
    IOC ioc;
    ioc.type = IOCType::Hash_SHA256;
    ioc.value = "abc123def456";
    ioc.source = "test";

    auto addResult = manager.addIOC(ioc);
    REQUIRE(addResult.isOk());
    uint64_t id = addResult.value();

    CHECK(manager.size() == 1);
    auto removeResult = manager.removeIOC(id);
    CHECK(removeResult.isOk());
    CHECK(manager.size() == 0);
}

TEST_CASE("IOCManager - Remove non-existent IOC fails") {
    IOCManager manager;
    auto result = manager.removeIOC(999);
    CHECK(result.isErr());
}

TEST_CASE("IOCManager - Update IOC") {
    IOCManager manager;
    IOC ioc;
    ioc.type = IOCType::IP;
    ioc.value = "10.0.0.1";
    ioc.source = "test";
    ioc.confidence = 0.5;

    auto addResult = manager.addIOC(ioc);
    REQUIRE(addResult.isOk());
    uint64_t id = addResult.value();

    IOC updated;
    updated.id = id;
    updated.type = IOCType::IP;
    updated.value = "10.0.0.1";
    updated.source = "updated_source";
    updated.confidence = 0.95;

    auto updateResult = manager.updateIOC(updated);
    CHECK(updateResult.isOk());

    auto getResult = manager.getIOCById(id);
    REQUIRE(getResult.isOk());
    CHECK(getResult.value().source == "updated_source");
    CHECK(getResult.value().confidence == doctest::Approx(0.95));
}

TEST_CASE("IOCManager - Search by value") {
    IOCManager manager;
    IOC ip1, ip2, domain1;
    ip1.type = IOCType::IP; ip1.value = "192.168.1.1"; ip1.source = "a";
    ip2.type = IOCType::IP; ip2.value = "10.0.0.5"; ip2.source = "b";
    domain1.type = IOCType::Domain; domain1.value = "evil.com"; domain1.source = "a";
    manager.addIOC(ip1);
    manager.addIOC(ip2);
    manager.addIOC(domain1);

    auto results = manager.searchByValue("192.168");
    CHECK(results.size() == 1);
    CHECK(results[0].value == "192.168.1.1");
}

TEST_CASE("IOCManager - Search by type") {
    IOCManager manager;
    IOC ip1, ip2, domain1, hash1;
    ip1.type = IOCType::IP; ip1.value = "192.168.1.1"; ip1.source = "a";
    ip2.type = IOCType::IP; ip2.value = "10.0.0.5"; ip2.source = "b";
    domain1.type = IOCType::Domain; domain1.value = "evil.com"; domain1.source = "a";
    hash1.type = IOCType::Hash_SHA256; hash1.value = "deadbeef123"; hash1.source = "c";
    manager.addIOC(ip1);
    manager.addIOC(ip2);
    manager.addIOC(domain1);
    manager.addIOC(hash1);

    auto ipResults = manager.searchByType(IOCType::IP);
    CHECK(ipResults.size() == 2);

    auto domainResults = manager.searchByType(IOCType::Domain);
    CHECK(domainResults.size() == 1);
    CHECK(domainResults[0].value == "evil.com");
}

TEST_CASE("IOCManager - Get active IOCs excludes inactive") {
    IOCManager manager;
    IOC active1, inactive1;
    active1.type = IOCType::IP; active1.value = "1.2.3.4"; active1.source = "s";
    active1.active = true;
    inactive1.type = IOCType::URL; inactive1.value = "http://old.com"; inactive1.source = "s";
    inactive1.active = false;
    manager.addIOC(active1);
    manager.addIOC(inactive1);

    auto active = manager.getActiveIOCs();
    CHECK(active.size() == 1);
    CHECK(active[0].value == "1.2.3.4");
}

TEST_CASE("IOCManager - Expired IOCs identified") {
    IOCManager manager;
    IOC expired;
    expired.type = IOCType::IP;
    expired.value = "1.2.3.4";
    expired.source = "test";
    expired.expirationDate = std::chrono::system_clock::now() - std::chrono::hours(24);
    manager.addIOC(expired);

    IOC fresh;
    fresh.type = IOCType::IP;
    fresh.value = "5.6.7.8";
    fresh.source = "test";
    fresh.expirationDate = std::chrono::system_clock::now() + std::chrono::hours(24);
    manager.addIOC(fresh);

    auto expiredIOCs = manager.getExpiredIOCs();
    CHECK(expiredIOCs.size() == 1);
    CHECK(expiredIOCs[0].value == "1.2.3.4");
}

TEST_CASE("IOCManager - No expiration not expired") {
    IOCManager manager;
    IOC noExpiry;
    noExpiry.type = IOCType::Domain;
    noExpiry.value = "test.org";
    noExpiry.source = "test";
    manager.addIOC(noExpiry);

    auto expiredIOCs = manager.getExpiredIOCs();
    CHECK(expiredIOCs.empty());
}

TEST_CASE("IOCManager - Thread safety concurrent adds") {
    IOCManager manager;
    constexpr int NUM_THREADS = 4;
    constexpr int OPS_PER_THREAD = 50;

    std::vector<std::thread> threads;
    for (int t = 0; t < NUM_THREADS; ++t) {
        threads.emplace_back([&manager, t]() {
            for (int i = 0; i < OPS_PER_THREAD; ++i) {
                IOC ioc;
                ioc.type = IOCType::IP;
                ioc.value = "10." + std::to_string(t) + ".0." + std::to_string(i);
                ioc.source = "thread_" + std::to_string(t);
                manager.addIOC(ioc);
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    CHECK(manager.size() == NUM_THREADS * OPS_PER_THREAD);
}

TEST_CASE("IOCManager - Thread safety concurrent reads") {
    IOCManager manager;
    for (int i = 0; i < 20; ++i) {
        IOC ioc;
        ioc.type = IOCType::Domain;
        ioc.value = "domain" + std::to_string(i) + ".com";
        ioc.source = "pre";
        manager.addIOC(ioc);
    }

    std::vector<std::thread> threads;
    for (int t = 0; t < 3; ++t) {
        threads.emplace_back([&manager]() {
            for (int i = 0; i < 50; ++i) {
                auto all = manager.getAllIOCs();
                CHECK(all.size() >= 20);
            }
        });
    }
    threads.emplace_back([&manager]() {
        for (int i = 0; i < 30; ++i) {
            IOC ioc;
            ioc.type = IOCType::URL;
            ioc.value = "http://new" + std::to_string(i) + ".com";
            ioc.source = "writer";
            manager.addIOC(ioc);
        }
    });

    for (auto& t : threads) {
        t.join();
    }

    CHECK(manager.size() == 50);
}
