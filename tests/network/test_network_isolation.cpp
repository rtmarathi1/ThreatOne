#include <doctest/doctest.h>
#include <network/NetworkIsolation.h>

using namespace ThreatOne::Network;

TEST_CASE("NetworkIsolation - initial state is not isolated") {
    NetworkIsolation isolation;
    CHECK_FALSE(isolation.isIsolated());
}

TEST_CASE("NetworkIsolation - enable isolation") {
    NetworkIsolation isolation;
    isolation.enableIsolation({"10.0.0.1", "10.0.0.2"});

    CHECK(isolation.isIsolated());
}

TEST_CASE("NetworkIsolation - disable isolation") {
    NetworkIsolation isolation;
    isolation.enableIsolation({"10.0.0.1"});
    CHECK(isolation.isIsolated());

    isolation.disableIsolation();
    CHECK_FALSE(isolation.isIsolated());
}

TEST_CASE("NetworkIsolation - management IPs are allowed when isolated") {
    NetworkIsolation isolation;
    isolation.enableIsolation({"192.168.1.1", "192.168.1.2"});

    CHECK(isolation.isAllowed("192.168.1.1"));
    CHECK(isolation.isAllowed("192.168.1.2"));
}

TEST_CASE("NetworkIsolation - non-management IPs are blocked when isolated") {
    NetworkIsolation isolation;
    isolation.enableIsolation({"192.168.1.1"});

    CHECK_FALSE(isolation.isAllowed("10.0.0.5"));
    CHECK_FALSE(isolation.isAllowed("8.8.8.8"));
}

TEST_CASE("NetworkIsolation - all IPs allowed when not isolated") {
    NetworkIsolation isolation;
    // Not isolated - all should pass
    CHECK(isolation.isAllowed("10.0.0.5"));
    CHECK(isolation.isAllowed("8.8.8.8"));
    CHECK(isolation.isAllowed("192.168.1.1"));
}

TEST_CASE("NetworkIsolation - getManagementIPs returns correct IPs") {
    NetworkIsolation isolation;
    isolation.enableIsolation({"10.0.0.1", "10.0.0.2", "10.0.0.3"});

    auto mgmtIPs = isolation.getManagementIPs();
    CHECK(mgmtIPs.size() == 3);
}

TEST_CASE("NetworkIsolation - re-enable with different management IPs") {
    NetworkIsolation isolation;
    isolation.enableIsolation({"10.0.0.1"});
    CHECK(isolation.isAllowed("10.0.0.1"));
    CHECK_FALSE(isolation.isAllowed("10.0.0.2"));

    isolation.enableIsolation({"10.0.0.2"});
    CHECK(isolation.isAllowed("10.0.0.2"));
    // Old management IP may or may not be cleared depending on implementation
}

TEST_CASE("NetworkIsolation - empty management IPs blocks all when isolated") {
    NetworkIsolation isolation;
    isolation.enableIsolation({});

    CHECK(isolation.isIsolated());
    CHECK_FALSE(isolation.isAllowed("10.0.0.1"));
    CHECK_FALSE(isolation.isAllowed("192.168.1.1"));
}
