#include <doctest/doctest.h>
#include <network/DNSFilter.h>

using namespace ThreatOne::Network;

TEST_CASE("DNSFilter - initial state is empty") {
    DNSFilter filter;
    CHECK(filter.getBlocklistSize() == 0);
    CHECK(filter.getAllowlistSize() == 0);
}

TEST_CASE("DNSFilter - blocklist blocks exact domains") {
    DNSFilter filter;
    filter.addToBlocklist("malware.com");

    auto result = filter.isAllowed("malware.com");
    CHECK(result.status == FilterResult::Status::Blocked);

    auto result2 = filter.isAllowed("safe.com");
    CHECK(result2.status == FilterResult::Status::Allowed);
}

TEST_CASE("DNSFilter - allowlist overrides blocklist") {
    DNSFilter filter;
    filter.addToBlocklist("example.com");
    filter.addToAllowlist("example.com");

    auto result = filter.isAllowed("example.com");
    CHECK(result.status == FilterResult::Status::Allowed);
}

TEST_CASE("DNSFilter - wildcard matching") {
    CHECK(DNSFilter::matchesWildcard("*.evil.com", "sub.evil.com"));
    CHECK(DNSFilter::matchesWildcard("*.evil.com", "deep.sub.evil.com"));
    // In this implementation, *.evil.com also matches evil.com
    CHECK(DNSFilter::matchesWildcard("*.evil.com", "evil.com"));
    CHECK_FALSE(DNSFilter::matchesWildcard("*.evil.com", "notevil.com"));
}

TEST_CASE("DNSFilter - wildcard blocklist integration") {
    DNSFilter filter;
    filter.addToBlocklist("*.malicious.org");

    auto result1 = filter.isAllowed("sub.malicious.org");
    CHECK(result1.status == FilterResult::Status::Blocked);

    // In this implementation, *.malicious.org also matches malicious.org
    auto result2 = filter.isAllowed("malicious.org");
    CHECK(result2.status == FilterResult::Status::Blocked);

    auto result3 = filter.isAllowed("safe.org");
    CHECK(result3.status == FilterResult::Status::Allowed);
}

TEST_CASE("DNSFilter - category-based blocking") {
    DNSFilter filter;
    filter.addDomainToCategory("gambling.com", "gambling");
    filter.addDomainToCategory("poker.net", "gambling");
    filter.addCategoryBlock("gambling");

    auto result1 = filter.isAllowed("gambling.com");
    CHECK(result1.status == FilterResult::Status::Blocked);

    auto result2 = filter.isAllowed("poker.net");
    CHECK(result2.status == FilterResult::Status::Blocked);

    auto result3 = filter.isAllowed("news.com");
    CHECK(result3.status == FilterResult::Status::Allowed);
}

TEST_CASE("DNSFilter - remove category block") {
    DNSFilter filter;
    filter.addDomainToCategory("gambling.com", "gambling");
    filter.addCategoryBlock("gambling");

    auto result = filter.isAllowed("gambling.com");
    CHECK(result.status == FilterResult::Status::Blocked);

    filter.removeCategoryBlock("gambling");
    auto result2 = filter.isAllowed("gambling.com");
    CHECK(result2.status == FilterResult::Status::Allowed);
}

TEST_CASE("DNSFilter - remove from blocklist") {
    DNSFilter filter;
    filter.addToBlocklist("bad.com");

    auto result = filter.isAllowed("bad.com");
    CHECK(result.status == FilterResult::Status::Blocked);

    filter.removeFromBlocklist("bad.com");
    auto result2 = filter.isAllowed("bad.com");
    CHECK(result2.status == FilterResult::Status::Allowed);
}

TEST_CASE("DNSFilter - remove from allowlist") {
    DNSFilter filter;
    filter.addToBlocklist("site.com");
    filter.addToAllowlist("site.com");

    auto result = filter.isAllowed("site.com");
    CHECK(result.status == FilterResult::Status::Allowed);

    filter.removeFromAllowlist("site.com");
    auto result2 = filter.isAllowed("site.com");
    CHECK(result2.status == FilterResult::Status::Blocked);
}

TEST_CASE("DNSFilter - empty domain handling") {
    DNSFilter filter;
    auto result = filter.isAllowed("");
    CHECK(result.status == FilterResult::Status::Allowed);
}

TEST_CASE("DNSFilter - blocklist size tracking") {
    DNSFilter filter;
    filter.addToBlocklist("a.com");
    filter.addToBlocklist("b.com");
    CHECK(filter.getBlocklistSize() == 2);

    filter.addToAllowlist("c.com");
    CHECK(filter.getAllowlistSize() == 1);
}
