#include "fleet/FleetManager.h"

#include <algorithm>
#include <sstream>
#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace ThreatOne::Fleet {

FleetManager::FleetManager()
    : logger_("FleetManager") {
    logger_.info("Fleet Manager initialized");
}

std::string FleetManager::generateId() const {
    std::ostringstream oss;
    oss << "ep-" << nextId_;
    return oss.str();
}

std::string FleetManager::registerEndpoint(const EndpointInfo& endpoint) {
    std::lock_guard<std::mutex> lock(mutex_);

    EndpointInfo ep = endpoint;
    if (ep.id.empty()) {
        ep.id = generateId();
        ++nextId_;
    }
    ep.status = EndpointStatus::Online;
    ep.lastHeartbeat = std::chrono::system_clock::now();

    endpoints_[ep.id] = ep;
    logger_.info("Registered endpoint: {} ({})", ep.id, ep.hostname);
    return ep.id;
}

bool FleetManager::deregisterEndpoint(const std::string& endpointId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = endpoints_.find(endpointId);
    if (it == endpoints_.end()) {
        return false;
    }

    // Remove from any group
    if (!it->second.groupId.empty()) {
        auto groupIt = groups_.find(it->second.groupId);
        if (groupIt != groups_.end()) {
            auto& ids = groupIt->second.endpointIds;
            ids.erase(std::remove(ids.begin(), ids.end(), endpointId), ids.end());
        }
    }

    endpoints_.erase(it);
    logger_.info("Deregistered endpoint: {}", endpointId);
    return true;
}

bool FleetManager::processHeartbeat(const HeartbeatData& heartbeat) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = endpoints_.find(heartbeat.endpointId);
    if (it == endpoints_.end()) {
        return false;
    }

    it->second.lastHeartbeat = heartbeat.timestamp;
    if (it->second.status == EndpointStatus::Offline) {
        it->second.status = EndpointStatus::Online;
    }

    // Mark degraded if resource usage is high
    if (heartbeat.cpuUsage > 90.0 || heartbeat.memUsage > 90.0) {
        it->second.status = EndpointStatus::Degraded;
    } else if (it->second.status == EndpointStatus::Degraded) {
        it->second.status = EndpointStatus::Online;
    }

    return true;
}

std::optional<EndpointInfo> FleetManager::getEndpoint(const std::string& endpointId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = endpoints_.find(endpointId);
    if (it == endpoints_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<EndpointInfo> FleetManager::getEndpoints() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<EndpointInfo> result;
    result.reserve(endpoints_.size());
    for (const auto& [id, ep] : endpoints_) {
        result.push_back(ep);
    }
    return result;
}

std::vector<EndpointInfo> FleetManager::getEndpointsByGroup(const std::string& groupId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<EndpointInfo> result;
    for (const auto& [id, ep] : endpoints_) {
        if (ep.groupId == groupId) {
            result.push_back(ep);
        }
    }
    return result;
}

std::vector<EndpointInfo> FleetManager::getEndpointsByStatus(EndpointStatus status) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<EndpointInfo> result;
    for (const auto& [id, ep] : endpoints_) {
        if (ep.status == status) {
            result.push_back(ep);
        }
    }
    return result;
}

std::string FleetManager::createGroup(const std::string& name, const std::string& description) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::ostringstream oss;
    oss << "grp-" << nextId_;
    ++nextId_;
    std::string groupId = oss.str();

    EndpointGroup group;
    group.id = groupId;
    group.name = name;
    group.description = description;

    groups_[groupId] = group;
    logger_.info("Created group: {} ({})", groupId, name);
    return groupId;
}

bool FleetManager::deleteGroup(const std::string& groupId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = groups_.find(groupId);
    if (it == groups_.end()) {
        return false;
    }

    // Remove group association from endpoints
    for (const auto& epId : it->second.endpointIds) {
        auto epIt = endpoints_.find(epId);
        if (epIt != endpoints_.end()) {
            epIt->second.groupId.clear();
        }
    }

    groups_.erase(it);
    logger_.info("Deleted group: {}", groupId);
    return true;
}

bool FleetManager::addToGroup(const std::string& endpointId, const std::string& groupId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto epIt = endpoints_.find(endpointId);
    if (epIt == endpoints_.end()) {
        return false;
    }

    auto groupIt = groups_.find(groupId);
    if (groupIt == groups_.end()) {
        return false;
    }

    // Remove from previous group if any
    if (!epIt->second.groupId.empty() && epIt->second.groupId != groupId) {
        auto prevGroupIt = groups_.find(epIt->second.groupId);
        if (prevGroupIt != groups_.end()) {
            auto& ids = prevGroupIt->second.endpointIds;
            ids.erase(std::remove(ids.begin(), ids.end(), endpointId), ids.end());
        }
    }

    epIt->second.groupId = groupId;

    // Avoid duplicate entries
    auto& ids = groupIt->second.endpointIds;
    if (std::find(ids.begin(), ids.end(), endpointId) == ids.end()) {
        ids.push_back(endpointId);
    }

    return true;
}

bool FleetManager::removeFromGroup(const std::string& endpointId, const std::string& groupId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto epIt = endpoints_.find(endpointId);
    if (epIt == endpoints_.end()) {
        return false;
    }

    auto groupIt = groups_.find(groupId);
    if (groupIt == groups_.end()) {
        return false;
    }

    if (epIt->second.groupId != groupId) {
        return false;
    }

    epIt->second.groupId.clear();
    auto& ids = groupIt->second.endpointIds;
    ids.erase(std::remove(ids.begin(), ids.end(), endpointId), ids.end());

    return true;
}

std::vector<EndpointGroup> FleetManager::getGroups() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<EndpointGroup> result;
    result.reserve(groups_.size());
    for (const auto& [id, group] : groups_) {
        result.push_back(group);
    }
    return result;
}

BulkOperationResult FleetManager::bulkOperation(BulkOperationType type,
                                                  const std::vector<std::string>& endpointIds) {
    std::lock_guard<std::mutex> lock(mutex_);

    BulkOperationResult result;
    result.totalTargets = static_cast<int>(endpointIds.size());

    for (const auto& epId : endpointIds) {
        auto it = endpoints_.find(epId);
        if (it == endpoints_.end()) {
            result.failureCount++;
            result.failedEndpoints.push_back(epId);
            continue;
        }

        // Simulate: only online endpoints can be operated on
        if (it->second.status == EndpointStatus::Online ||
            it->second.status == EndpointStatus::Degraded) {
            result.successCount++;
        } else {
            result.failureCount++;
            result.failedEndpoints.push_back(epId);
        }
    }

    logger_.info("Bulk operation completed: {}/{} successful",
                 result.successCount, result.totalTargets);
    return result;
}

void FleetManager::checkHeartbeatTimeouts() {
    std::lock_guard<std::mutex> lock(mutex_);

    auto now = std::chrono::system_clock::now();

    for (auto& [id, ep] : endpoints_) {
        if (ep.status == EndpointStatus::Maintenance) {
            continue;
        }

        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - ep.lastHeartbeat);
        if (elapsed > heartbeatTimeout_) {
            if (ep.status != EndpointStatus::Offline) {
                ep.status = EndpointStatus::Offline;
                logger_.warn("Endpoint {} marked offline (heartbeat timeout)", id);
            }
        }
    }
}

void FleetManager::setHeartbeatTimeout(std::chrono::seconds timeout) {
    std::lock_guard<std::mutex> lock(mutex_);
    heartbeatTimeout_ = timeout;
}

} // namespace ThreatOne::Fleet
