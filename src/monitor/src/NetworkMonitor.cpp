#include "monitor/NetworkMonitor.h"

#include <chrono>
#include <sstream>
#include <algorithm>

namespace ThreatOne::Monitor {

NetworkMonitor::NetworkMonitor()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("NetworkMonitor")) {
    logger_.info("NetworkMonitor initialized");
}

std::string NetworkMonitor::generateConnectionId() {
    return "CONN-" + std::to_string(nextConnId_++);
}

void NetworkMonitor::addInterface(const NetworkInterface& iface) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Update existing or add new
    for (auto& existing : interfaces_) {
        if (existing.name == iface.name) {
            existing = iface;
            return;
        }
    }
    interfaces_.push_back(iface);
    logger_.info("Added network interface: {}", iface.name);
}

bool NetworkMonitor::updateInterface(const std::string& name, uint64_t rxBytes, uint64_t txBytes) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& iface : interfaces_) {
        if (iface.name == name) {
            iface.rxBytes = rxBytes;
            iface.txBytes = txBytes;
            return true;
        }
    }
    return false;
}

std::vector<NetworkInterface> NetworkMonitor::getInterfaces() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return interfaces_;
}

NetworkInterface NetworkMonitor::getInterface(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& iface : interfaces_) {
        if (iface.name == name) {
            return iface;
        }
    }
    return {};
}

void NetworkMonitor::addConnection(const NetworkConnection& conn) {
    std::lock_guard<std::mutex> lock(mutex_);

    NetworkConnection newConn = conn;
    if (newConn.id.empty()) {
        newConn.id = generateConnectionId();
    }
    connections_[newConn.id] = newConn;
    stats_.totalConnections++;
    if (newConn.state == ConnectionState::Established || newConn.state == ConnectionState::Listen) {
        stats_.activeConnections++;
    }
}

void NetworkMonitor::removeConnection(const std::string& connId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = connections_.find(connId);
    if (it != connections_.end()) {
        if (it->second.state == ConnectionState::Established || it->second.state == ConnectionState::Listen) {
            if (stats_.activeConnections > 0) {
                stats_.activeConnections--;
            }
        }
        connections_.erase(it);
    }
}

std::vector<NetworkConnection> NetworkMonitor::getConnections() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<NetworkConnection> result;
    result.reserve(connections_.size());
    for (const auto& [id, conn] : connections_) {
        result.push_back(conn);
    }
    return result;
}

std::vector<NetworkConnection> NetworkMonitor::getConnectionsByState(ConnectionState state) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<NetworkConnection> result;
    for (const auto& [id, conn] : connections_) {
        if (conn.state == state) {
            result.push_back(conn);
        }
    }
    return result;
}

uint64_t NetworkMonitor::getActiveConnectionCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_.activeConnections;
}

NetworkStats NetworkMonitor::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void NetworkMonitor::updateStats(uint64_t bytesIn, uint64_t bytesOut, uint64_t pktsIn, uint64_t pktsOut) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.totalBytesIn += bytesIn;
    stats_.totalBytesOut += bytesOut;
    stats_.totalPacketsIn += pktsIn;
    stats_.totalPacketsOut += pktsOut;
    stats_.packetRateIn = static_cast<double>(pktsIn);
    stats_.packetRateOut = static_cast<double>(pktsOut);
}

void NetworkMonitor::resetStats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_ = {};
    stats_.totalConnections = connections_.size();
    stats_.activeConnections = 0;
    for (const auto& [id, conn] : connections_) {
        if (conn.state == ConnectionState::Established || conn.state == ConnectionState::Listen) {
            stats_.activeConnections++;
        }
    }
}

double NetworkMonitor::getTotalBandwidthUsage() const {
    std::lock_guard<std::mutex> lock(mutex_);

    double total = 0.0;
    for (const auto& iface : interfaces_) {
        total += iface.bandwidth;
    }
    return total;
}

} // namespace ThreatOne::Monitor
