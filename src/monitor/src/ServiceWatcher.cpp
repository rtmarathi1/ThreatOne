#include "monitor/ServiceWatcher.h"
#include <mutex>

#include <chrono>
#include <sstream>

namespace ThreatOne::Monitor {

ServiceWatcher::ServiceWatcher()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("ServiceWatcher")) {
    logger_.info("ServiceWatcher initialized");
}

std::string ServiceWatcher::generateServiceId() {
    return "SVC-" + std::to_string(nextServiceId_++);
}

std::string ServiceWatcher::generateEventId() {
    return "SVCEVT-" + std::to_string(nextEventId_++);
}

std::string ServiceWatcher::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << time;
    return oss.str();
}

std::string ServiceWatcher::addService(const ServiceInfo& service) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (service.name.empty()) {
        return "";
    }

    std::string id = generateServiceId();
    ServiceInfo newService = service;
    newService.id = id;
    if (newService.lastStatusChange.empty()) {
        newService.lastStatusChange = getCurrentTimestamp();
    }
    services_[id] = newService;

    logger_.info("Added service: {} ({})", service.name, id);
    return id;
}

bool ServiceWatcher::removeService(const std::string& serviceId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = services_.find(serviceId);
    if (it == services_.end()) {
        return false;
    }
    services_.erase(it);
    return true;
}

bool ServiceWatcher::updateServiceStatus(const std::string& serviceId, ServiceStatus newStatus, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = services_.find(serviceId);
    if (it == services_.end()) {
        return false;
    }

    ServiceStatus previousStatus = it->second.status;
    it->second.status = newStatus;
    it->second.lastStatusChange = getCurrentTimestamp();

    if (newStatus == ServiceStatus::Running && previousStatus != ServiceStatus::Running) {
        it->second.restartCount++;
    }

    // Record event
    ServiceEvent event;
    event.id = generateEventId();
    event.serviceId = serviceId;
    event.serviceName = it->second.name;
    event.previousStatus = previousStatus;
    event.newStatus = newStatus;
    event.reason = reason;
    event.timestamp = getCurrentTimestamp();
    events_.push_back(event);

    logger_.info("Service {} status changed: {} -> {}",
                 it->second.name, static_cast<int>(previousStatus), static_cast<int>(newStatus));
    return true;
}

std::vector<ServiceInfo> ServiceWatcher::getServices() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ServiceInfo> result;
    result.reserve(services_.size());
    for (const auto& [id, svc] : services_) {
        result.push_back(svc);
    }
    return result;
}

ServiceInfo ServiceWatcher::getService(const std::string& serviceId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = services_.find(serviceId);
    if (it != services_.end()) {
        return it->second;
    }
    return {};
}

std::vector<ServiceInfo> ServiceWatcher::getRunningServices() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ServiceInfo> result;
    for (const auto& [id, svc] : services_) {
        if (svc.status == ServiceStatus::Running) {
            result.push_back(svc);
        }
    }
    return result;
}

std::vector<ServiceInfo> ServiceWatcher::getFailedServices() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ServiceInfo> result;
    for (const auto& [id, svc] : services_) {
        if (svc.status == ServiceStatus::Failed) {
            result.push_back(svc);
        }
    }
    return result;
}

std::vector<ServiceInfo> ServiceWatcher::getStoppedServices() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ServiceInfo> result;
    for (const auto& [id, svc] : services_) {
        if (svc.status == ServiceStatus::Stopped) {
            result.push_back(svc);
        }
    }
    return result;
}

std::vector<ServiceEvent> ServiceWatcher::getEvents() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return events_;
}

std::vector<ServiceEvent> ServiceWatcher::getEventsForService(const std::string& serviceId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ServiceEvent> result;
    for (const auto& event : events_) {
        if (event.serviceId == serviceId) {
            result.push_back(event);
        }
    }
    return result;
}

std::vector<ServiceEvent> ServiceWatcher::getRecentEvents(size_t count) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ServiceEvent> result;
    size_t start = events_.size() > count ? events_.size() - count : 0;
    for (size_t i = start; i < events_.size(); ++i) {
        result.push_back(events_[i]);
    }
    return result;
}

ServiceWatcherStats ServiceWatcher::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);

    ServiceWatcherStats stats;
    stats.totalServices = services_.size();
    stats.totalEvents = events_.size();

    for (const auto& [id, svc] : services_) {
        switch (svc.status) {
            case ServiceStatus::Running:
                stats.runningServices++;
                break;
            case ServiceStatus::Stopped:
                stats.stoppedServices++;
                break;
            case ServiceStatus::Failed:
                stats.failedServices++;
                break;
            default:
                break;
        }
        stats.totalRestarts += svc.restartCount;
    }

    return stats;
}

uint64_t ServiceWatcher::getRestartCount(const std::string& serviceId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = services_.find(serviceId);
    if (it != services_.end()) {
        return it->second.restartCount;
    }
    return 0;
}

} // namespace ThreatOne::Monitor
