#include <doctest/doctest.h>
#include <firewall/ConnectionTracker.h>
#include <string>

using namespace ThreatOne::Firewall;

TEST_CASE("ConnectionTracker - initial state is empty") {
    ConnectionTracker tracker;
    CHECK(tracker.connectionCount() == 0);
    CHECK(tracker.getConnections().empty());
}

TEST_CASE("ConnectionTracker - parse /proc/net/tcp format") {
    ConnectionTracker tracker;

    // /proc/net/tcp format: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
    // IP is in little-endian hex, port in hex
    // 0100007F:0050 = 127.0.0.1:80
    // 0101A8C0:1F90 = 192.168.1.1:8080
    // State 01 = ESTABLISHED
    std::string procData =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 0100007F:0050 0101A8C0:1F90 01 00000000:00000000 00:00000000 00000000     0        0 12345\n";

    tracker.parseProcNet(procData, Protocol::TCP);

    auto connections = tracker.getConnections();
    REQUIRE(connections.size() == 1);
    CHECK(connections[0].localPort == 80);
    CHECK(connections[0].remotePort == 8080);
    CHECK(connections[0].state == "ESTABLISHED");
}

TEST_CASE("ConnectionTracker - parse multiple connections") {
    ConnectionTracker tracker;

    std::string procData =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 0100007F:0050 0101A8C0:1F90 01 00000000:00000000 00:00000000 00000000     0        0 12345\n"
        "   1: 0100007F:01BB 0201A8C0:C350 06 00000000:00000000 00:00000000 00000000     0        0 12346\n";

    tracker.parseProcNet(procData, Protocol::TCP);

    CHECK(tracker.connectionCount() == 2);
    auto connections = tracker.getConnections();
    CHECK(connections[0].localPort == 80);
    CHECK(connections[1].localPort == 443);
}

TEST_CASE("ConnectionTracker - state code mapping") {
    ConnectionTracker tracker;

    // State 01 = ESTABLISHED
    std::string data1 =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 0100007F:0050 0100007F:1F90 01 00000000:00000000 00:00000000 00000000     0        0 100\n";
    tracker.parseProcNet(data1, Protocol::TCP);
    auto conns = tracker.getConnections();
    REQUIRE(!conns.empty());
    CHECK(conns[0].state == "ESTABLISHED");
}

TEST_CASE("ConnectionTracker - state 0A is LISTEN") {
    ConnectionTracker tracker;

    std::string data =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 100\n";
    tracker.parseProcNet(data, Protocol::TCP);
    auto conns = tracker.getConnections();
    REQUIRE(!conns.empty());
    CHECK(conns[0].state == "LISTEN");
}

TEST_CASE("ConnectionTracker - getConnectionByPort") {
    ConnectionTracker tracker;

    std::string procData =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 0100007F:0050 0100007F:1F90 01 00000000:00000000 00:00000000 00000000     0        0 100\n"
        "   1: 0100007F:01BB 0100007F:C350 01 00000000:00000000 00:00000000 00000000     0        0 101\n";

    tracker.parseProcNet(procData, Protocol::TCP);

    auto portConns = tracker.getConnectionByPort(80);
    REQUIRE(portConns.size() == 1);
    CHECK(portConns[0].localPort == 80);

    auto noConns = tracker.getConnectionByPort(9999);
    CHECK(noConns.empty());
}

TEST_CASE("ConnectionTracker - handle malformed input") {
    ConnectionTracker tracker;

    // Empty string
    tracker.parseProcNet("", Protocol::TCP);
    CHECK(tracker.connectionCount() == 0);

    // Only header
    tracker.parseProcNet("  sl  local_address rem_address   st\n", Protocol::TCP);
    CHECK(tracker.connectionCount() == 0);
}

TEST_CASE("ConnectionTracker - state transitions") {
    CHECK(ConnectionTracker::stateToString(ConnectionState::New) == "NEW");
    CHECK(ConnectionTracker::stateToString(ConnectionState::Established) == "ESTABLISHED");
    CHECK(ConnectionTracker::stateToString(ConnectionState::Closing) == "CLOSING");
    CHECK(ConnectionTracker::stateToString(ConnectionState::Closed) == "CLOSED");

    // Test state transitions
    auto newState = ConnectionTracker::transitionState(ConnectionState::New, "ESTABLISHED");
    CHECK(newState == ConnectionState::Established);

    auto closingState = ConnectionTracker::transitionState(ConnectionState::Established, "FIN_WAIT1");
    CHECK(closingState == ConnectionState::Closing);

    auto closedState = ConnectionTracker::transitionState(ConnectionState::Closing, "CLOSE");
    CHECK(closedState == ConnectionState::Closed);
}

TEST_CASE("ConnectionTracker - connectionCountByState") {
    ConnectionTracker tracker;

    std::string procData =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 0100007F:0050 0100007F:1F90 01 00000000:00000000 00:00000000 00000000     0        0 100\n"
        "   1: 0100007F:01BB 0100007F:C350 01 00000000:00000000 00:00000000 00000000     0        0 101\n"
        "   2: 0100007F:1F91 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 102\n";

    tracker.parseProcNet(procData, Protocol::TCP);

    CHECK(tracker.connectionCountByState("ESTABLISHED") == 2);
    CHECK(tracker.connectionCountByState("LISTEN") == 1);
    CHECK(tracker.connectionCountByState("CLOSE_WAIT") == 0);
}
