#include "cloud/DeviceManager.h"

#include <algorithm>

namespace ThreatOne::Cloud {

DeviceManager::DeviceManager()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("DeviceManager")) {
    logger_.info("DeviceManager initialized");
}

std::string DeviceManager::generateDeviceId() {
    return "DEV-" + std::to_string(nextDeviceId_++);
}

std::string DeviceManager::registerDevice(const DeviceInfo& device) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = device.id.empty() ? generateDeviceId() : device.id;
    DeviceInfo stored = device;
    stored.id = id;
    stored.registeredAt = "now";
    if (stored.lastSeen.empty()) {
        stored.lastSeen = "now";
    }
    devices_[id] = stored;

    logger_.info("Registered device: id={}, hostname={}", id, device.hostname);
    return id;
}

bool DeviceManager::unregisterDevice(const std::string& deviceId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = devices_.find(deviceId);
    if (it == devices_.end()) {
        logger_.warn("unregisterDevice: device {} not found", deviceId);
        return false;
    }

    logger_.info("Unregistered device: id={}, hostname={}", deviceId, it->second.hostname);
    devices_.erase(it);
    return true;
}

std::vector<DeviceInfo> DeviceManager::getDevices() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<DeviceInfo> result;
    result.reserve(devices_.size());
    for (const auto& [id, device] : devices_) {
        result.push_back(device);
    }
    return result;
}

DeviceInfo DeviceManager::getDevice(const std::string& deviceId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = devices_.find(deviceId);
    if (it == devices_.end()) {
        return {};
    }
    return it->second;
}

bool DeviceManager::updateDeviceStatus(const std::string& deviceId, DeviceStatus status) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = devices_.find(deviceId);
    if (it == devices_.end()) {
        logger_.warn("updateDeviceStatus: device {} not found", deviceId);
        return false;
    }

    it->second.status = status;
    logger_.info("Updated device {} status to {}", deviceId, static_cast<int>(status));
    return true;
}

bool DeviceManager::updateLastSeen(const std::string& deviceId, const std::string& timestamp) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = devices_.find(deviceId);
    if (it == devices_.end()) {
        logger_.warn("updateLastSeen: device {} not found", deviceId);
        return false;
    }

    it->second.lastSeen = timestamp;
    return true;
}

std::vector<DeviceInfo> DeviceManager::getOnlineDevices() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<DeviceInfo> result;
    for (const auto& [id, device] : devices_) {
        if (device.status == DeviceStatus::Online) {
            result.push_back(device);
        }
    }
    return result;
}

std::vector<DeviceInfo> DeviceManager::getOfflineDevices() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<DeviceInfo> result;
    for (const auto& [id, device] : devices_) {
        if (device.status == DeviceStatus::Offline) {
            result.push_back(device);
        }
    }
    return result;
}

bool DeviceManager::updateHealthScore(const std::string& deviceId, int score) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = devices_.find(deviceId);
    if (it == devices_.end()) {
        logger_.warn("updateHealthScore: device {} not found", deviceId);
        return false;
    }

    it->second.healthScore = score;
    logger_.info("Updated device {} health score to {}", deviceId, score);
    return true;
}

std::vector<DeviceInfo> DeviceManager::getUnhealthyDevices(int threshold) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<DeviceInfo> result;
    for (const auto& [id, device] : devices_) {
        if (device.healthScore < threshold) {
            result.push_back(device);
        }
    }
    return result;
}

size_t DeviceManager::getDeviceCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return devices_.size();
}

bool DeviceManager::hasDevice(const std::string& deviceId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return devices_.count(deviceId) > 0;
}

} // namespace ThreatOne::Cloud
