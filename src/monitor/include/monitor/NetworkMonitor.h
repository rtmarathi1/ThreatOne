#pragma once

#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>
#include <cstdint>

namespace ThreatOne::Monitor {

enum class ConnectionState {
    Established,
    Listen,
    TimeWait,
    CloseWait,
    Closed
};

struct NetworkInterface {
    std::string name;
    std::string ipAddress;
    std::string macAddress;
    bool up = false;
    uint64_t rxBytes = 0;
    uint64_t txBytes = 0;
    uint64_t rxPackets = 0;
    uint64_t txPackets = 0;
    double bandwidth = 0.0;
};

struct NetworkConnection {
    std::string id;
    std::string localAddress;
    uint16_t localPort = 0;
    std::string remoteAddress;
    uint16_t remotePort = 0;
    ConnectionState state = ConnectionState::Established;
    std::string protocol;
    uint64_t pid = 0;
    std::string processName;
};

struct NetworkStats {
    uint64_t totalConnections = 0;
    uint64_t activeConnections = 0;
    uint64_t totalBytesIn = 0;
    uint64_t totalBytesOut = 0;
    uint64_t totalPacketsIn = 0;
    uint64_t totalPacketsOut = 0;
    double packetRateIn = 0.0;
    double packetRateOut = 0.0;
};

class NetworkMonitor {
public:
    NetworkMonitor();
    ~NetworkMonitor() = default;

    // Interface monitoring
    void addInterface(const NetworkInterface& iface);
    bool updateInterface(const std::string& name, uint64_t rxBytes, uint64_t txBytes);
    [[nodiscard]] std::vector<NetworkInterface> getInterfaces() const;
    [[nodiscard]] NetworkInterface getInterface(const std::string& name) const;

    // Connection tracking
    void addConnection(const NetworkConnection& conn);
    void removeConnection(const std::string& connId);
    [[nodiscard]] std::vector<NetworkConnection> getConnections() const;
    [[nodiscard]] std::vector<NetworkConnection> getConnectionsByState(ConnectionState state) const;
    [[nodiscard]] uint64_t getActiveConnectionCount() const;

    // Statistics
    [[nodiscard]] NetworkStats getStats() const;
    void updateStats(uint64_t bytesIn, uint64_t bytesOut, uint64_t pktsIn, uint64_t pktsOut);
    void resetStats();

    // Bandwidth
    [[nodiscard]] double getTotalBandwidthUsage() const;

private:
    std::string generateConnectionId();

    mutable std::mutex mutex_;
    std::vector<NetworkInterface> interfaces_;
    std::map<std::string, NetworkConnection> connections_;
    NetworkStats stats_;

    int nextConnId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Monitor
