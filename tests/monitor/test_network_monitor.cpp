#include <doctest/doctest.h>
#include <monitor/NetworkMonitor.h>

using namespace ThreatOne::Monitor;

TEST_CASE("NetworkMonitor - Add interface") {
    NetworkMonitor netmon;

    NetworkInterface iface;
    iface.name = "eth0";
    iface.ipAddress = "192.168.1.100";
    iface.macAddress = "00:11:22:33:44:55";
    iface.up = true;
    iface.rxBytes = 1000;
    iface.txBytes = 500;

    netmon.addInterface(iface);

    auto interfaces = netmon.getInterfaces();
    REQUIRE(interfaces.size() == 1);
    CHECK(interfaces[0].name == "eth0");
    CHECK(interfaces[0].ipAddress == "192.168.1.100");
}

TEST_CASE("NetworkMonitor - Update existing interface") {
    NetworkMonitor netmon;

    NetworkInterface iface;
    iface.name = "eth0";
    iface.rxBytes = 100;
    iface.txBytes = 50;
    netmon.addInterface(iface);

    // Adding with same name updates
    NetworkInterface updated;
    updated.name = "eth0";
    updated.rxBytes = 200;
    updated.txBytes = 100;
    netmon.addInterface(updated);

    auto interfaces = netmon.getInterfaces();
    CHECK(interfaces.size() == 1);
    CHECK(interfaces[0].rxBytes == 200);
}

TEST_CASE("NetworkMonitor - Update interface stats") {
    NetworkMonitor netmon;

    NetworkInterface iface;
    iface.name = "eth0";
    netmon.addInterface(iface);

    CHECK(netmon.updateInterface("eth0", 5000, 3000));
    CHECK_FALSE(netmon.updateInterface("nonexistent", 0, 0));

    auto i = netmon.getInterface("eth0");
    CHECK(i.rxBytes == 5000);
    CHECK(i.txBytes == 3000);
}

TEST_CASE("NetworkMonitor - Add and get connections") {
    NetworkMonitor netmon;

    NetworkConnection conn;
    conn.localAddress = "192.168.1.100";
    conn.localPort = 8080;
    conn.remoteAddress = "10.0.0.1";
    conn.remotePort = 443;
    conn.state = ConnectionState::Established;
    conn.protocol = "TCP";
    conn.pid = 1234;

    netmon.addConnection(conn);

    auto connections = netmon.getConnections();
    REQUIRE(connections.size() == 1);
    CHECK(connections[0].localPort == 8080);
    CHECK(connections[0].state == ConnectionState::Established);
}

TEST_CASE("NetworkMonitor - Remove connection") {
    NetworkMonitor netmon;

    NetworkConnection conn;
    conn.id = "test-conn";
    conn.state = ConnectionState::Established;
    netmon.addConnection(conn);

    netmon.removeConnection("test-conn");
    CHECK(netmon.getConnections().empty());
}

TEST_CASE("NetworkMonitor - Filter connections by state") {
    NetworkMonitor netmon;

    NetworkConnection conn1;
    conn1.state = ConnectionState::Established;
    netmon.addConnection(conn1);

    NetworkConnection conn2;
    conn2.state = ConnectionState::Listen;
    netmon.addConnection(conn2);

    NetworkConnection conn3;
    conn3.state = ConnectionState::TimeWait;
    netmon.addConnection(conn3);

    auto established = netmon.getConnectionsByState(ConnectionState::Established);
    CHECK(established.size() == 1);

    auto listening = netmon.getConnectionsByState(ConnectionState::Listen);
    CHECK(listening.size() == 1);
}

TEST_CASE("NetworkMonitor - Active connection count") {
    NetworkMonitor netmon;

    NetworkConnection conn1;
    conn1.state = ConnectionState::Established;
    netmon.addConnection(conn1);

    NetworkConnection conn2;
    conn2.state = ConnectionState::Established;
    netmon.addConnection(conn2);

    NetworkConnection conn3;
    conn3.state = ConnectionState::Closed;
    netmon.addConnection(conn3);

    CHECK(netmon.getActiveConnectionCount() == 2);
}

TEST_CASE("NetworkMonitor - Stats") {
    NetworkMonitor netmon;

    netmon.updateStats(1000, 500, 100, 50);
    auto stats = netmon.getStats();
    CHECK(stats.totalBytesIn == 1000);
    CHECK(stats.totalBytesOut == 500);
    CHECK(stats.totalPacketsIn == 100);
    CHECK(stats.totalPacketsOut == 50);

    netmon.updateStats(2000, 1000, 200, 100);
    stats = netmon.getStats();
    CHECK(stats.totalBytesIn == 3000);
}

TEST_CASE("NetworkMonitor - Reset stats") {
    NetworkMonitor netmon;
    netmon.updateStats(1000, 500, 100, 50);
    netmon.resetStats();
    auto stats = netmon.getStats();
    CHECK(stats.totalBytesIn == 0);
}

TEST_CASE("NetworkMonitor - Bandwidth usage") {
    NetworkMonitor netmon;

    NetworkInterface iface;
    iface.name = "eth0";
    iface.bandwidth = 100.5;
    netmon.addInterface(iface);

    CHECK(netmon.getTotalBandwidthUsage() == doctest::Approx(100.5));
}
