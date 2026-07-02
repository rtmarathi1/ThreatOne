#include "firewall/ConnectionTracker.h"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace ThreatOne::Firewall {

ConnectionTracker::ConnectionTracker()
    : logger_(Core::Logger::instance().getModuleLogger("ConnectionTracker")) {
    logger_.info("ConnectionTracker initialized");
}

void ConnectionTracker::refresh() {
    // Read /proc/net/tcp
    std::ifstream tcpFile("/proc/net/tcp");
    if (tcpFile.is_open()) {
        std::string content((std::istreambuf_iterator<char>(tcpFile)),
                            std::istreambuf_iterator<char>());
        parseProcNet(content, Protocol::TCP);
    }

    // Read /proc/net/udp
    std::ifstream udpFile("/proc/net/udp");
    if (udpFile.is_open()) {
        std::string content((std::istreambuf_iterator<char>(udpFile)),
                            std::istreambuf_iterator<char>());
        parseProcNet(content, Protocol::UDP);
    }

    logger_.debug("Refreshed connections, total: {}", connections_.size());
}

void ConnectionTracker::parseProcNet(const std::string& data, Protocol protocol) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Clear existing connections for this protocol
    connections_.erase(
        std::remove_if(connections_.begin(), connections_.end(),
            [protocol](const ConnectionInfo& ci) { return ci.protocol == protocol; }),
        connections_.end());

    std::istringstream stream(data);
    std::string line;

    // Skip header line
    std::getline(stream, line);

    while (std::getline(stream, line)) {
        if (line.empty()) continue;

        std::istringstream lineStream(line);
        std::string slot, localAddr, remAddr, stateHex;
        // Format: sl local_address rem_address st ...
        lineStream >> slot >> localAddr >> remAddr >> stateHex;

        if (localAddr.empty() || remAddr.empty()) continue;

        // Parse local address (IP:Port in hex)
        auto localColon = localAddr.find(':');
        if (localColon == std::string::npos) continue;

        std::string localIPHex = localAddr.substr(0, localColon);
        std::string localPortHex = localAddr.substr(localColon + 1);

        // Parse remote address
        auto remColon = remAddr.find(':');
        if (remColon == std::string::npos) continue;

        std::string remIPHex = remAddr.substr(0, remColon);
        std::string remPortHex = remAddr.substr(remColon + 1);

        // Parse state
        int stateCode = 0;
        try {
            stateCode = std::stoi(stateHex, nullptr, 16);
        } catch (...) {
            continue;
        }

        // Read remaining fields to get inode/pid if available
        std::string txQueue, rxQueue, timer, retrnsmt, uid, timeout, inode;
        lineStream >> txQueue >> rxQueue >> timer >> retrnsmt >> uid >> timeout >> inode;

        ConnectionInfo info;
        info.localAddress = parseHexIP(localIPHex);
        info.localPort = parseHexPort(localPortHex);
        info.remoteAddress = parseHexIP(remIPHex);
        info.remotePort = parseHexPort(remPortHex);
        info.protocol = protocol;
        info.state = mapTcpState(stateCode);

        if (!inode.empty()) {
            try {
                info.processId = std::stoull(inode);
            } catch (...) {
                info.processId = 0;
            }
        }

        connections_.push_back(std::move(info));
    }
}

std::vector<ConnectionInfo> ConnectionTracker::getConnections() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return connections_;
}

std::vector<ConnectionInfo> ConnectionTracker::getConnectionByPort(uint16_t port) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ConnectionInfo> result;
    for (const auto& conn : connections_) {
        if (conn.localPort == port || conn.remotePort == port) {
            result.push_back(conn);
        }
    }
    return result;
}

size_t ConnectionTracker::connectionCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return connections_.size();
}

size_t ConnectionTracker::connectionCountByState(const std::string& state) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return static_cast<size_t>(std::count_if(connections_.begin(), connections_.end(),
        [&state](const ConnectionInfo& ci) { return ci.state == state; }));
}

ConnectionState ConnectionTracker::transitionState(ConnectionState current, const std::string& tcpState) {
    if (tcpState == "ESTABLISHED") {
        return ConnectionState::Established;
    }
    if (tcpState == "SYN_SENT" || tcpState == "SYN_RECV") {
        return ConnectionState::New;
    }
    if (tcpState == "FIN_WAIT1" || tcpState == "FIN_WAIT2" ||
        tcpState == "TIME_WAIT" || tcpState == "CLOSE_WAIT" ||
        tcpState == "LAST_ACK" || tcpState == "CLOSING") {
        return ConnectionState::Closing;
    }
    if (tcpState == "CLOSE") {
        return ConnectionState::Closed;
    }
    return current;
}

std::string ConnectionTracker::stateToString(ConnectionState state) {
    switch (state) {
        case ConnectionState::New: return "NEW";
        case ConnectionState::Established: return "ESTABLISHED";
        case ConnectionState::Closing: return "CLOSING";
        case ConnectionState::Closed: return "CLOSED";
    }
    return "UNKNOWN";
}

std::string ConnectionTracker::parseHexIP(const std::string& hexIP) {
    if (hexIP.size() < 8) return "0.0.0.0";

    unsigned long ipVal = 0;
    try {
        ipVal = std::stoul(hexIP, nullptr, 16);
    } catch (...) {
        return "0.0.0.0";
    }

    // /proc/net/tcp stores IP in little-endian (host byte order on little-endian systems)
    uint8_t b1 = static_cast<uint8_t>(ipVal & 0xFF);
    uint8_t b2 = static_cast<uint8_t>((ipVal >> 8) & 0xFF);
    uint8_t b3 = static_cast<uint8_t>((ipVal >> 16) & 0xFF);
    uint8_t b4 = static_cast<uint8_t>((ipVal >> 24) & 0xFF);

    return std::to_string(b1) + "." + std::to_string(b2) + "." +
           std::to_string(b3) + "." + std::to_string(b4);
}

uint16_t ConnectionTracker::parseHexPort(const std::string& hexPort) {
    try {
        return static_cast<uint16_t>(std::stoul(hexPort, nullptr, 16));
    } catch (...) {
        return 0;
    }
}

std::string ConnectionTracker::mapTcpState(int stateCode) {
    switch (stateCode) {
        case 0x01: return "ESTABLISHED";
        case 0x02: return "SYN_SENT";
        case 0x03: return "SYN_RECV";
        case 0x04: return "FIN_WAIT1";
        case 0x05: return "FIN_WAIT2";
        case 0x06: return "TIME_WAIT";
        case 0x07: return "CLOSE";
        case 0x08: return "CLOSE_WAIT";
        case 0x09: return "LAST_ACK";
        case 0x0A: return "LISTEN";
        case 0x0B: return "CLOSING";
        default: return "UNKNOWN";
    }
}

} // namespace ThreatOne::Firewall
