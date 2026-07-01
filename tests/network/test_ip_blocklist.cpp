#include <doctest/doctest.h>
#include <network/IPBlocklist.h>

using namespace ThreatOne::Network;

TEST_CASE("IPBlocklist - initial state is empty") {
    IPBlocklist blocklist;
    CHECK(blocklist.getBlockedCount() == 0);
    CHECK_FALSE(blocklist.isBlocked("1.2.3.4"));
}

TEST_CASE("IPBlocklist - add and check single IP") {
    IPBlocklist blocklist;
    blocklist.addIP("192.168.1.1");

    CHECK(blocklist.isBlocked("192.168.1.1"));
    CHECK_FALSE(blocklist.isBlocked("192.168.1.2"));
    CHECK(blocklist.getBlockedCount() == 1);
}

TEST_CASE("IPBlocklist - add multiple IPs") {
    IPBlocklist blocklist;
    blocklist.addIP("10.0.0.1");
    blocklist.addIP("10.0.0.2");
    blocklist.addIP("10.0.0.3");

    CHECK(blocklist.isBlocked("10.0.0.1"));
    CHECK(blocklist.isBlocked("10.0.0.2"));
    CHECK(blocklist.isBlocked("10.0.0.3"));
    CHECK_FALSE(blocklist.isBlocked("10.0.0.4"));
    CHECK(blocklist.getBlockedCount() == 3);
}

TEST_CASE("IPBlocklist - remove IP") {
    IPBlocklist blocklist;
    blocklist.addIP("1.2.3.4");
    blocklist.addIP("5.6.7.8");

    blocklist.removeIP("1.2.3.4");
    CHECK_FALSE(blocklist.isBlocked("1.2.3.4"));
    CHECK(blocklist.isBlocked("5.6.7.8"));
}

TEST_CASE("IPBlocklist - CIDR range blocking") {
    IPBlocklist blocklist;
    blocklist.addRange("10.0.0.0/8");

    CHECK(blocklist.isBlocked("10.0.0.1"));
    CHECK(blocklist.isBlocked("10.1.2.3"));
    CHECK(blocklist.isBlocked("10.255.255.255"));
    CHECK_FALSE(blocklist.isBlocked("11.0.0.1"));
    CHECK_FALSE(blocklist.isBlocked("192.168.1.1"));
}

TEST_CASE("IPBlocklist - /24 CIDR range") {
    IPBlocklist blocklist;
    blocklist.addRange("192.168.1.0/24");

    CHECK(blocklist.isBlocked("192.168.1.0"));
    CHECK(blocklist.isBlocked("192.168.1.128"));
    CHECK(blocklist.isBlocked("192.168.1.255"));
    CHECK_FALSE(blocklist.isBlocked("192.168.2.1"));
    CHECK_FALSE(blocklist.isBlocked("192.168.0.255"));
}

TEST_CASE("IPBlocklist - bulk import") {
    IPBlocklist blocklist;
    std::vector<std::string> ips = {"1.1.1.1", "2.2.2.2", "3.3.3.3"};
    blocklist.importList(ips);

    CHECK(blocklist.isBlocked("1.1.1.1"));
    CHECK(blocklist.isBlocked("2.2.2.2"));
    CHECK(blocklist.isBlocked("3.3.3.3"));
    CHECK_FALSE(blocklist.isBlocked("4.4.4.4"));
}

TEST_CASE("IPBlocklist - clear resets the list") {
    IPBlocklist blocklist;
    blocklist.addIP("1.2.3.4");
    blocklist.addIP("5.6.7.8");
    blocklist.addRange("10.0.0.0/8");

    blocklist.clear();
    CHECK(blocklist.getBlockedCount() == 0);
    CHECK_FALSE(blocklist.isBlocked("1.2.3.4"));
    CHECK_FALSE(blocklist.isBlocked("10.0.0.1"));
}

TEST_CASE("IPBlocklist - edge case IPs") {
    IPBlocklist blocklist;
    blocklist.addIP("0.0.0.0");
    blocklist.addIP("255.255.255.255");

    CHECK(blocklist.isBlocked("0.0.0.0"));
    CHECK(blocklist.isBlocked("255.255.255.255"));
    CHECK_FALSE(blocklist.isBlocked("128.0.0.1"));
}

TEST_CASE("IPBlocklist - /16 CIDR range") {
    IPBlocklist blocklist;
    blocklist.addRange("172.16.0.0/16");

    CHECK(blocklist.isBlocked("172.16.0.1"));
    CHECK(blocklist.isBlocked("172.16.255.255"));
    CHECK_FALSE(blocklist.isBlocked("172.17.0.1"));
}
