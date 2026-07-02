#include "threat_intel/IOCManager.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <utility>
#include <vector>

namespace ThreatOne::ThreatIntel {

IOCManager::IOCManager()
    : logger_(Core::Logger::instance().getModuleLogger("ThreatIntel.IOCManager")) {
}

Core::Result<uint64_t> IOCManager::addIOC(IOC ioc) {
    std::unique_lock lock(mutex_);

    if (ioc.value.empty()) {
        return Core::Result<uint64_t>::err(
            Core::Error("IOC value cannot be empty", Core::ErrorCategory::Validation));
    }

    if (ioc.id == 0) {
        ioc.id = nextId_++;
    } else {
        if (iocs_.contains(ioc.id)) {
            return Core::Result<uint64_t>::err(
                Core::Error("IOC with this ID already exists", Core::ErrorCategory::Validation));
        }
        if (ioc.id >= nextId_) {
            nextId_ = ioc.id + 1;
        }
    }

    uint64_t id = ioc.id;
    iocs_.emplace(id, std::move(ioc));
    logger_.debug("Added IOC id={}", id);
    return Core::Result<uint64_t>::ok(id);
}

Core::Result<void> IOCManager::removeIOC(uint64_t id) {
    std::unique_lock lock(mutex_);

    auto it = iocs_.find(id);
    if (it == iocs_.end()) {
        return Core::Result<void>::err(
            Core::Error("IOC not found", Core::ErrorCategory::Validation));
    }

    iocs_.erase(it);
    logger_.debug("Removed IOC id={}", id);
    return Core::Result<void>::ok();
}

Core::Result<void> IOCManager::updateIOC(const IOC& ioc) {
    std::unique_lock lock(mutex_);

    auto it = iocs_.find(ioc.id);
    if (it == iocs_.end()) {
        return Core::Result<void>::err(
            Core::Error("IOC not found for update", Core::ErrorCategory::Validation));
    }

    if (ioc.value.empty()) {
        return Core::Result<void>::err(
            Core::Error("IOC value cannot be empty", Core::ErrorCategory::Validation));
    }

    it->second = ioc;
    logger_.debug("Updated IOC id={}", ioc.id);
    return Core::Result<void>::ok();
}

Core::Result<IOC> IOCManager::getIOCById(uint64_t id) const {
    std::shared_lock lock(mutex_);

    auto it = iocs_.find(id);
    if (it == iocs_.end()) {
        return Core::Result<IOC>::err(
            Core::Error("IOC not found", Core::ErrorCategory::Validation));
    }

    return Core::Result<IOC>::ok(it->second);
}

std::vector<IOC> IOCManager::getAllIOCs() const {
    std::shared_lock lock(mutex_);

    std::vector<IOC> result;
    result.reserve(iocs_.size());
    for (const auto& [id, ioc] : iocs_) {
        result.push_back(ioc);
    }
    return result;
}

std::vector<IOC> IOCManager::searchByValue(const std::string& value) const {
    std::shared_lock lock(mutex_);

    std::vector<IOC> result;
    for (const auto& [id, ioc] : iocs_) {
        if (ioc.value.find(value) != std::string::npos) {
            result.push_back(ioc);
        }
    }
    return result;
}

std::vector<IOC> IOCManager::searchByType(IOCType type) const {
    std::shared_lock lock(mutex_);

    std::vector<IOC> result;
    for (const auto& [id, ioc] : iocs_) {
        if (ioc.type == type) {
            result.push_back(ioc);
        }
    }
    return result;
}

std::vector<IOC> IOCManager::getExpiredIOCs() const {
    std::shared_lock lock(mutex_);

    auto now = std::chrono::system_clock::now();
    std::vector<IOC> result;
    for (const auto& [id, ioc] : iocs_) {
        // Only consider IOCs with a non-default expiration date
        if (ioc.expirationDate != std::chrono::system_clock::time_point{} &&
            ioc.expirationDate < now) {
            result.push_back(ioc);
        }
    }
    return result;
}

std::vector<IOC> IOCManager::getActiveIOCs() const {
    std::shared_lock lock(mutex_);

    std::vector<IOC> result;
    for (const auto& [id, ioc] : iocs_) {
        if (ioc.active) {
            result.push_back(ioc);
        }
    }
    return result;
}

size_t IOCManager::size() const {
    std::shared_lock lock(mutex_);
    return iocs_.size();
}

void IOCManager::clear() {
    std::unique_lock lock(mutex_);
    iocs_.clear();
    logger_.info("IOC store cleared");
}

} // namespace ThreatOne::ThreatIntel
