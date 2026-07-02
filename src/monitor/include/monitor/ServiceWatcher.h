#pragma once

#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>
#include <cstdint>

namespace ThreatOne::Monitor {

enum class ServiceStatus {
    Running,
    Stopped,
    Starting,
    Stopping,
    Failed,
    Unknown
};

struct ServiceInfo {
    std::string id;
    std::string name;
    std::string displayName;
    ServiceStatus status = ServiceStatus::Unknown;
    uint64_t pid = 0;
    uint64_t uptimeSeconds = 0;
    uint64_t restartCount = 0;
    std::string lastStatusChange;
    bool autoRestart = false;
    bool monitored = true;
};

struct ServiceEvent {
    std::string id;
    std::string serviceId;
    std::string serviceName;
    ServiceStatus previousStatus = ServiceStatus::Unknown;
    ServiceStatus newStatus = ServiceStatus::Unknown;
    std::string reason;
    std::string timestamp;
};

struct ServiceWatcherStats {
    uint64_t totalServices = 0;
    uint64_t runningServices = 0;
    uint64_t stoppedServices = 0;
    uint64_t failedServices = 0;
    uint64_t totalEvents = 0;
    uint64_t totalRestarts = 0;
};

class ServiceWatcher {
public:
    ServiceWatcher();
    ~ServiceWatcher() = default;

    // Service management
    std::string addService(const ServiceInfo& service);
    bool removeService(const std::string& serviceId);
    bool updateServiceStatus(const std::string& serviceId, ServiceStatus newStatus, const std::string& reason = "");
    [[nodiscard]] std::vector<ServiceInfo> getServices() const;
    [[nodiscard]] ServiceInfo getService(const std::string& serviceId) const;

    // Monitoring
    [[nodiscard]] std::vector<ServiceInfo> getRunningServices() const;
    [[nodiscard]] std::vector<ServiceInfo> getFailedServices() const;
    [[nodiscard]] std::vector<ServiceInfo> getStoppedServices() const;

    // Events
    [[nodiscard]] std::vector<ServiceEvent> getEvents() const;
    [[nodiscard]] std::vector<ServiceEvent> getEventsForService(const std::string& serviceId) const;
    [[nodiscard]] std::vector<ServiceEvent> getRecentEvents(size_t count) const;

    // Stats
    [[nodiscard]] ServiceWatcherStats getStats() const;
    [[nodiscard]] uint64_t getRestartCount(const std::string& serviceId) const;

private:
    std::string generateServiceId();
    std::string generateEventId();
    std::string getCurrentTimestamp() const;

    mutable std::mutex mutex_;
    std::map<std::string, ServiceInfo> services_;
    std::vector<ServiceEvent> events_;

    int nextServiceId_ = 1;
    int nextEventId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Monitor
