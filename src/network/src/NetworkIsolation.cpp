#include "network/NetworkIsolation.h"

namespace ThreatOne::Network {

NetworkIsolation::NetworkIsolation()
    : logger_(Core::Logger::instance().getModuleLogger("NetworkIsolation")) {
    logger_.info("NetworkIsolation initialized");
}

void NetworkIsolation::enableIsolation(const std::vector<std::string>& managementIPs) {
    std::lock_guard<std::mutex> lock(mutex_);
    isolated_ = true;
    managementIPs_.clear();
    for (const auto& ip : managementIPs) {
        managementIPs_.insert(ip);
    }
    logger_.warn("Network isolation ENABLED - only {} management IPs allowed",
                 managementIPs_.size());
}

void NetworkIsolation::disableIsolation() {
    std::lock_guard<std::mutex> lock(mutex_);
    isolated_ = false;
    managementIPs_.clear();
    logger_.info("Network isolation DISABLED");
}

bool NetworkIsolation::isIsolated() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return isolated_;
}

bool NetworkIsolation::isAllowed(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!isolated_) {
        return true; // Not isolated, everything allowed
    }
    return managementIPs_.count(ip) > 0;
}

std::vector<std::string> NetworkIsolation::getManagementIPs() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return {managementIPs_.begin(), managementIPs_.end()};
}

} // namespace ThreatOne::Network
