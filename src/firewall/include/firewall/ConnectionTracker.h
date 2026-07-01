#pragma once

#include "firewall/IFirewallManager.h"
#include "core/Logger.h"

#include <vector>
#include <string>
#include <mutex>
#include <cstdint>
#include <unordered_map>

namespace ThreatOne::Firewall {

// Connection states for the state machine
enum class ConnectionState {
    New,
    Established,
    Closing,
    Closed
};

class ConnectionTracker {
public:
    ConnectionTracker();
    ~ConnectionTracker() = default;

    // Refresh connections from /proc/net/tcp and /proc/net/udp
    void refresh();

    // Parse proc net data from a string (for testability)
    void parseProcNet(const std::string& data, Protocol protocol);

    // Accessors
    std::vector<ConnectionInfo> getConnections() const;
    std::vector<ConnectionInfo> getConnectionByPort(uint16_t port) const;

    // Statistics
    size_t connectionCount() const;
    size_t connectionCountByState(const std::string& state) const;

    // State machine transition
    static ConnectionState transitionState(ConnectionState current, const std::string& tcpState);
    static std::string stateToString(ConnectionState state);

private:
    // Parse a hex IP:port from /proc/net/tcp format
    static std::string parseHexIP(const std::string& hexIP);
    static uint16_t parseHexPort(const std::string& hexPort);
    static std::string mapTcpState(int stateCode);

    mutable std::mutex mutex_;
    std::vector<ConnectionInfo> connections_;
    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Firewall
