#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <cstdint>
#include <mutex>

#include "core/Logger.h"

namespace ThreatOne::Network {

class GeoIPDatabase {
public:
    GeoIPDatabase();

    void addMapping(const std::string& cidrRange, const std::string& countryCode);
    std::string lookupCountry(const std::string& ip) const;
    void loadDefaultMappings();

private:
    struct GeoMapping {
        uint32_t network;
        uint32_t mask;
        std::string countryCode;
    };

    static uint32_t ipToUint32(const std::string& ip);

    mutable std::mutex mutex_;
    std::vector<GeoMapping> mappings_;
    Core::ModuleLogger logger_;
};

class GeoBlocker {
public:
    GeoBlocker();
    explicit GeoBlocker(std::shared_ptr<GeoIPDatabase> db);

    void setDatabase(std::shared_ptr<GeoIPDatabase> db);
    void addBlockedCountry(const std::string& code);
    void removeBlockedCountry(const std::string& code);
    bool isBlocked(const std::string& ip) const;
    std::vector<std::string> getBlockedCountries() const;

private:
    mutable std::mutex mutex_;
    std::shared_ptr<GeoIPDatabase> database_;
    std::unordered_set<std::string> blockedCountries_;
    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Network
