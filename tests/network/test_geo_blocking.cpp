#include <doctest/doctest.h>
#include <network/GeoIPDatabase.h>

#include <memory>

using namespace ThreatOne::Network;

TEST_CASE("GeoIPDatabase - initial state returns empty for lookup") {
    GeoIPDatabase db;
    CHECK(db.lookupCountry("1.2.3.4").empty());
}

TEST_CASE("GeoIPDatabase - add mapping and lookup") {
    GeoIPDatabase db;
    db.addMapping("192.168.1.0/24", "US");

    CHECK(db.lookupCountry("192.168.1.5") == "US");
    CHECK(db.lookupCountry("192.168.1.255") == "US");
    CHECK(db.lookupCountry("192.168.2.1").empty());
}

TEST_CASE("GeoIPDatabase - multiple country mappings") {
    GeoIPDatabase db;
    db.addMapping("10.0.0.0/8", "US");
    db.addMapping("172.16.0.0/16", "DE");

    CHECK(db.lookupCountry("10.1.2.3") == "US");
    CHECK(db.lookupCountry("172.16.5.5") == "DE");
    CHECK(db.lookupCountry("8.8.8.8").empty());
}

TEST_CASE("GeoBlocker - initial state blocks nothing") {
    auto db = std::make_shared<GeoIPDatabase>();
    db->addMapping("10.0.0.0/8", "CN");
    GeoBlocker blocker(db);

    CHECK_FALSE(blocker.isBlocked("10.1.2.3"));
}

TEST_CASE("GeoBlocker - add country block") {
    auto db = std::make_shared<GeoIPDatabase>();
    db->addMapping("10.0.0.0/8", "CN");
    db->addMapping("172.16.0.0/16", "RU");

    GeoBlocker blocker(db);
    blocker.addBlockedCountry("CN");

    CHECK(blocker.isBlocked("10.1.2.3"));
    CHECK_FALSE(blocker.isBlocked("172.16.1.1"));
}

TEST_CASE("GeoBlocker - IP not in blocked country is allowed") {
    auto db = std::make_shared<GeoIPDatabase>();
    db->addMapping("10.0.0.0/8", "US");
    db->addMapping("172.16.0.0/16", "CN");

    GeoBlocker blocker(db);
    blocker.addBlockedCountry("CN");

    CHECK_FALSE(blocker.isBlocked("10.1.2.3"));
    CHECK(blocker.isBlocked("172.16.5.5"));
}

TEST_CASE("GeoBlocker - remove country unblocks") {
    auto db = std::make_shared<GeoIPDatabase>();
    db->addMapping("10.0.0.0/8", "RU");

    GeoBlocker blocker(db);
    blocker.addBlockedCountry("RU");
    CHECK(blocker.isBlocked("10.1.2.3"));

    blocker.removeBlockedCountry("RU");
    CHECK_FALSE(blocker.isBlocked("10.1.2.3"));
}

TEST_CASE("GeoBlocker - getBlockedCountries") {
    auto db = std::make_shared<GeoIPDatabase>();
    GeoBlocker blocker(db);

    blocker.addBlockedCountry("CN");
    blocker.addBlockedCountry("RU");
    blocker.addBlockedCountry("IR");

    auto countries = blocker.getBlockedCountries();
    CHECK(countries.size() == 3);
}

TEST_CASE("GeoBlocker - unknown IP is not blocked") {
    auto db = std::make_shared<GeoIPDatabase>();
    db->addMapping("10.0.0.0/8", "CN");

    GeoBlocker blocker(db);
    blocker.addBlockedCountry("CN");

    // IP not in any mapping should not be blocked
    CHECK_FALSE(blocker.isBlocked("8.8.8.8"));
}

TEST_CASE("GeoBlocker - multiple blocked countries") {
    auto db = std::make_shared<GeoIPDatabase>();
    db->addMapping("10.0.0.0/8", "CN");
    db->addMapping("172.16.0.0/16", "RU");
    db->addMapping("192.168.0.0/16", "US");

    GeoBlocker blocker(db);
    blocker.addBlockedCountry("CN");
    blocker.addBlockedCountry("RU");

    CHECK(blocker.isBlocked("10.1.2.3"));
    CHECK(blocker.isBlocked("172.16.1.1"));
    CHECK_FALSE(blocker.isBlocked("192.168.1.1"));
}
