#pragma once

#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>
#include <cstdint>

namespace ThreatOne::Cloud {

enum class DeviceStatus {
    Online,
    Offline,
    Degraded,
    Maintenance
};

struct DeviceInfo {
    std::string id;
    std::string hostname;
    std::string ipAddress;
    std::string osType;
    std::string osVersion;
    std::string agentVersion;
    DeviceStatus status = DeviceStatus::Offline;
    std::string lastSeen;
    std::string registeredAt;
    int healthScore = 100;
};

class DeviceManager {
public:
    DeviceManager();
    ~DeviceManager() = default;

    // Device registration
    std::string registerDevice(const DeviceInfo& device);
    bool unregisterDevice(const std::string& deviceId);
    [[nodiscard]] std::vector<DeviceInfo> getDevices() const;
    [[nodiscard]] DeviceInfo getDevice(const std::string& deviceId) const;

    // Status management
    bool updateDeviceStatus(const std::string& deviceId, DeviceStatus status);
    bool updateLastSeen(const std::string& deviceId, const std::string& timestamp);
    [[nodiscard]] std::vector<DeviceInfo> getOnlineDevices() const;
    [[nodiscard]] std::vector<DeviceInfo> getOfflineDevices() const;

    // Health tracking
    bool updateHealthScore(const std::string& deviceId, int score);
    [[nodiscard]] std::vector<DeviceInfo> getUnhealthyDevices(int threshold = 50) const;

    // Queries
    [[nodiscard]] size_t getDeviceCount() const;
    [[nodiscard]] bool hasDevice(const std::string& deviceId) const;

private:
    std::string generateDeviceId();

    mutable std::mutex mutex_;
    std::map<std::string, DeviceInfo> devices_;
    int nextDeviceId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Cloud
