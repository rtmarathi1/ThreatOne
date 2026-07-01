#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <chrono>
#include <mutex>

#include "network/INetworkManager.h"
#include "core/Logger.h"

namespace ThreatOne::Network {

struct ConnectionStats {
    std::string connectionId;
    std::string appPath;
    uint64_t bytesSent = 0;
    uint64_t bytesReceived = 0;
};

struct AppStats {
    std::string appPath;
    uint64_t totalBytesSent = 0;
    uint64_t totalBytesReceived = 0;
    size_t connectionCount = 0;
};

class BandwidthMonitor {
public:
    BandwidthMonitor();

    void recordTraffic(const std::string& connectionId, const std::string& appPath,
                       uint64_t bytesSent, uint64_t bytesReceived);

    std::unordered_map<std::string, ConnectionStats> getStats() const;
    AppStats getAppStats(const std::string& appPath) const;
    TrafficStats getTotalStats() const;

    void setRateLimit(const std::string& appPath, uint64_t bytesPerSecond);
    bool checkRateLimit(const std::string& appPath, uint64_t bytes) const;

    void reset();

private:
    struct RateWindow {
        uint64_t bytesPerSecond = 0;
        mutable std::vector<std::pair<std::chrono::steady_clock::time_point, uint64_t>> windowEntries;
    };

    mutable std::mutex mutex_;
    std::unordered_map<std::string, ConnectionStats> connectionStats_;
    std::unordered_map<std::string, RateWindow> rateLimits_;
    Core::ModuleLogger logger_;

    uint64_t getCurrentWindowBytes(const RateWindow& window) const;
};

} // namespace ThreatOne::Network
