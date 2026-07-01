#pragma once

// ThreatOne Threat Intel - IOC Manager
// Thread-safe CRUD operations for Indicators of Compromise

#include <string>
#include <vector>
#include <unordered_map>
#include <shared_mutex>
#include <cstdint>

#include <core/Error.h>
#include <core/Logger.h>
#include "IOCTypes.h"

namespace ThreatOne::ThreatIntel {

// Manages a collection of IOCs with thread-safe CRUD operations
class IOCManager {
public:
    IOCManager();

    // Add a new IOC, assigns an ID if id == 0
    [[nodiscard]] Core::Result<uint64_t> addIOC(IOC ioc);

    // Remove an IOC by ID
    [[nodiscard]] Core::Result<void> removeIOC(uint64_t id);

    // Update an existing IOC (must have valid id)
    [[nodiscard]] Core::Result<void> updateIOC(const IOC& ioc);

    // Get a single IOC by ID
    [[nodiscard]] Core::Result<IOC> getIOCById(uint64_t id) const;

    // Get all IOCs
    [[nodiscard]] std::vector<IOC> getAllIOCs() const;

    // Search IOCs by value (substring match)
    [[nodiscard]] std::vector<IOC> searchByValue(const std::string& value) const;

    // Search IOCs by type
    [[nodiscard]] std::vector<IOC> searchByType(IOCType type) const;

    // Get expired IOCs (expirationDate < now)
    [[nodiscard]] std::vector<IOC> getExpiredIOCs() const;

    // Get active IOCs only
    [[nodiscard]] std::vector<IOC> getActiveIOCs() const;

    // Get total count
    [[nodiscard]] size_t size() const;

    // Clear all IOCs
    void clear();

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<uint64_t, IOC> iocs_;
    uint64_t nextId_ = 1;
    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::ThreatIntel
