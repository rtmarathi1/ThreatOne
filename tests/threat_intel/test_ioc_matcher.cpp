#include <doctest/doctest.h>
#include <threat_intel/IOCMatcher.h>

using namespace ThreatOne::ThreatIntel;

TEST_CASE("IOCMatcher - Exact hash matching") {
    IOCMatcher matcher;

    IOC hashIOC;
    hashIOC.id = 1;
    hashIOC.type = IOCType::Hash_SHA256;
    hashIOC.value = "e3b0c44298fc1c149afbf4c8996fb924";
    hashIOC.confidence = 0.95;
    hashIOC.active = true;
    matcher.addIOC(hashIOC);

    IOC emailIOC;
    emailIOC.id = 2;
    emailIOC.type = IOCType::EmailAddress;
    emailIOC.value = "attacker@evil.com";
    emailIOC.confidence = 0.8;
    emailIOC.active = true;
    matcher.addIOC(emailIOC);

    SUBCASE("Exact match on hash") {
        auto results = matcher.matchExact("e3b0c44298fc1c149afbf4c8996fb924");
        REQUIRE(results.size() == 1);
        CHECK(results[0].matchedIOC.id == 1);
        CHECK(results[0].matchType == "exact");
        CHECK(results[0].confidence == doctest::Approx(0.95));
    }

    SUBCASE("Exact match on email") {
        auto results = matcher.matchExact("attacker@evil.com");
        REQUIRE(results.size() == 1);
        CHECK(results[0].matchedIOC.id == 2);
    }

    SUBCASE("No match for unknown value") {
        auto results = matcher.matchExact("unknown_value");
        CHECK(results.empty());
    }
}

TEST_CASE("IOCMatcher - Domain suffix matching") {
    IOCMatcher matcher;

    IOC domainIOC;
    domainIOC.id = 10;
    domainIOC.type = IOCType::Domain;
    domainIOC.value = "evil.com";
    domainIOC.confidence = 0.9;
    domainIOC.active = true;
    matcher.addIOC(domainIOC);

    SUBCASE("Exact domain match") {
        auto results = matcher.matchDomain("evil.com");
        CHECK(!results.empty());
        CHECK(results[0].matchedIOC.value == "evil.com");
    }

    SUBCASE("Subdomain suffix match") {
        auto results = matcher.matchDomain("sub.evil.com");
        CHECK(!results.empty());
        // Subdomain match has slightly lower confidence
        CHECK(results[0].confidence < 0.9);
    }

    SUBCASE("Non-matching domain") {
        auto results = matcher.matchDomain("good.org");
        CHECK(results.empty());
    }

    SUBCASE("Partial suffix does not match") {
        // "notevil.com" should NOT match "evil.com" since it lacks the dot separator
        auto results = matcher.matchDomain("notevil.com");
        CHECK(results.empty());
    }
}

TEST_CASE("IOCMatcher - IP prefix matching") {
    IOCMatcher matcher;

    IOC ipIOC;
    ipIOC.id = 20;
    ipIOC.type = IOCType::IP;
    ipIOC.value = "192.168.1.100";
    ipIOC.confidence = 0.85;
    ipIOC.active = true;
    matcher.addIOC(ipIOC);

    SUBCASE("Exact IP match via trie") {
        auto results = matcher.matchIP("192.168.1.100");
        CHECK(!results.empty());
        CHECK(results[0].matchedIOC.id == 20);
    }

    SUBCASE("IP entry count") {
        CHECK(matcher.ipEntryCount() == 1);
    }
}

TEST_CASE("IOCMatcher - URL matching") {
    IOCMatcher matcher;

    IOC urlIOC;
    urlIOC.id = 30;
    urlIOC.type = IOCType::URL;
    urlIOC.value = "http://malware.com/payload";
    urlIOC.confidence = 0.92;
    urlIOC.active = true;
    matcher.addIOC(urlIOC);

    SUBCASE("Exact URL match") {
        auto results = matcher.matchURL("http://malware.com/payload");
        CHECK(!results.empty());
        CHECK(results[0].matchedIOC.id == 30);
    }

    SUBCASE("URL with matching domain") {
        // The URL's domain "malware.com" should also be indexed
        auto results = matcher.matchDomain("malware.com");
        CHECK(!results.empty());
    }
}

TEST_CASE("IOCMatcher - matchAll combines results") {
    IOCMatcher matcher;

    IOC ipIOC;
    ipIOC.id = 100;
    ipIOC.type = IOCType::IP;
    ipIOC.value = "10.0.0.1";
    ipIOC.confidence = 0.7;
    ipIOC.active = true;
    matcher.addIOC(ipIOC);

    IOC hashIOC;
    hashIOC.id = 101;
    hashIOC.type = IOCType::Hash_MD5;
    hashIOC.value = "d41d8cd98f00b204e9800998ecf8427e";
    hashIOC.confidence = 0.99;
    hashIOC.active = true;
    matcher.addIOC(hashIOC);

    SUBCASE("matchAll finds IP") {
        auto results = matcher.matchAll("10.0.0.1");
        CHECK(!results.empty());
    }

    SUBCASE("matchAll finds hash") {
        auto results = matcher.matchAll("d41d8cd98f00b204e9800998ecf8427e");
        CHECK(!results.empty());
    }

    SUBCASE("matchAll deduplicates") {
        auto results = matcher.matchAll("10.0.0.1");
        // Each IOC ID should appear only once
        std::unordered_map<uint64_t, int> idCount;
        for (const auto& r : results) {
            idCount[r.matchedIOC.id]++;
        }
        for (const auto& [id, count] : idCount) {
            CHECK(count == 1);
        }
    }
}

TEST_CASE("IOCMatcher - Load from IOCManager") {
    IOCManager manager;

    IOC ioc1;
    ioc1.type = IOCType::Hash_SHA256;
    ioc1.value = "abc123";
    ioc1.source = "test";
    ioc1.active = true;
    manager.addIOC(ioc1);

    IOC ioc2;
    ioc2.type = IOCType::Domain;
    ioc2.value = "bad.org";
    ioc2.source = "test";
    ioc2.active = true;
    manager.addIOC(ioc2);

    IOCMatcher matcher;
    matcher.loadIOCs(manager);

    SUBCASE("Loaded IOCs are matchable") {
        auto results = matcher.matchExact("abc123");
        CHECK(!results.empty());

        auto domResults = matcher.matchDomain("bad.org");
        CHECK(!domResults.empty());
    }

    SUBCASE("Clear removes all") {
        matcher.clear();
        auto results = matcher.matchExact("abc123");
        CHECK(results.empty());
    }
}
