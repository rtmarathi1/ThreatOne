#pragma once

// ThreatOne Fleet - Fleet Manager
// Endpoint registration, heartbeat monitoring, status tracking, group management

#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <optional>
#include <mutex>
#include <functional>

#include "core/Logger.h"

namespace ThreatOne::Fleet {

enum class EndpointStatus {
    Online,
    Offline,
    Degraded,
    Maintenance
};

struct EndpointInfo {
    std::string id;
    std::string hostname;
    std::string ipAddress;
    std::string os;
    std::string agentVersion;
    std::chrono::system_clock::time_point lastHeartbeat;
    EndpointStatus status = EndpointStatus::Offline;
    std::string groupId;
    std::vector<std::string> tags;
};

struct EndpointGroup {
    std::string id;
    std::string name;
    std::string description;
    std::vector<std::string> endpointIds;
};

struct HeartbeatData {
    std::string endpointId;
    std::chrono::system_clock::time_point timestamp;
    double cpuUsage = 0.0;
    double memUsage = 0.0;
    int threatCount = 0;
};

enum class BulkOperationType {
    Scan,
    Restart,
    Update,
    ConfigPush
};

struct BulkOperationResult {
    int totalTargets = 0;
    int successCount = 0;
    int failureCount = 0;
    std::vector<std::string> failedEndpoints;
};

class IFleetManager {
public:
    virtual ~IFleetManager() = default;

    virtual std::string registerEndpoint(const EndpointInfo& endpoint) = 0;
    virtual bool deregisterEndpoint(const std::string& endpointId) = 0;
    virtual bool processHeartbeat(const HeartbeatData& heartbeat) = 0;
    virtual std::optional<EndpointInfo> getEndpoint(const std::string& endpointId) const = 0;
    virtual std::vector<EndpointInfo> getEndpoints() const = 0;
    virtual std::vector<EndpointInfo> getEndpointsByGroup(const std::string& groupId) const = 0;
    virtual std::vector<EndpointInfo> getEndpointsByStatus(EndpointStatus status) const = 0;

    virtual std::string createGroup(const std::string& name, const std::string& description) = 0;
    virtual bool deleteGroup(const std::string& groupId) = 0;
    virtual bool addToGroup(const std::string& endpointId, const std::string& groupId) = 0;
    virtual bool removeFromGroup(const std::string& endpointId, const std::string& groupId) = 0;
    virtual std::vector<EndpointGroup> getGroups() const = 0;

    virtual BulkOperationResult bulkOperation(BulkOperationType type,
                                               const std::vector<std::string>& endpointIds) = 0;

    virtual void checkHeartbeatTimeouts() = 0;
    virtual void setHeartbeatTimeout(std::chrono::seconds timeout) = 0;
};

class FleetManager : public IFleetManager {
public:
    FleetManager();
    ~FleetManager() override = default;

    std::string registerEndpoint(const EndpointInfo& endpoint) override;
    bool deregisterEndpoint(const std::string& endpointId) override;
    bool processHeartbeat(const HeartbeatData& heartbeat) override;
    std::optional<EndpointInfo> getEndpoint(const std::string& endpointId) const override;
    std::vector<EndpointInfo> getEndpoints() const override;
    std::vector<EndpointInfo> getEndpointsByGroup(const std::string& groupId) const override;
    std::vector<EndpointInfo> getEndpointsByStatus(EndpointStatus status) const override;

    std::string createGroup(const std::string& name, const std::string& description) override;
    bool deleteGroup(const std::string& groupId) override;
    bool addToGroup(const std::string& endpointId, const std::string& groupId) override;
    bool removeFromGroup(const std::string& endpointId, const std::string& groupId) override;
    std::vector<EndpointGroup> getGroups() const override;

    BulkOperationResult bulkOperation(BulkOperationType type,
                                       const std::vector<std::string>& endpointIds) override;

    void checkHeartbeatTimeouts() override;
    void setHeartbeatTimeout(std::chrono::seconds timeout) override;

private:
    std::string generateId() const;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, EndpointInfo> endpoints_;
    std::unordered_map<std::string, EndpointGroup> groups_;
    std::chrono::seconds heartbeatTimeout_{60};
    int nextId_ = 1;
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Fleet
