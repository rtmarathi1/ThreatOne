#include "network/GeoIPDatabase.h"

#include <sstream>
#include <algorithm>

namespace ThreatOne::Network {

// --- GeoIPDatabase ---

GeoIPDatabase::GeoIPDatabase()
    : logger_(Core::Logger::instance().getModuleLogger("GeoIPDatabase")) {
    logger_.info("GeoIPDatabase initialized");
}

uint32_t GeoIPDatabase::ipToUint32(const std::string& ip) {
    uint32_t result = 0;
    uint32_t octet = 0;
    int shift = 24;

    for (char c : ip) {
        if (c == '.') {
            result |= (octet << shift);
            shift -= 8;
            octet = 0;
        } else if (c >= '0' && c <= '9') {
            octet = octet * 10 + static_cast<uint32_t>(c - '0');
        } else {
            return 0;
        }
    }
    result |= (octet << shift);
    return result;
}

void GeoIPDatabase::addMapping(const std::string& cidrRange, const std::string& countryCode) {
    auto slashPos = cidrRange.find('/');
    uint32_t network = 0;
    uint32_t mask = 0xFFFFFFFF;

    if (slashPos != std::string::npos) {
        std::string ipPart = cidrRange.substr(0, slashPos);
        int prefix = std::stoi(cidrRange.substr(slashPos + 1));
        network = ipToUint32(ipPart);
        mask = (prefix == 0) ? 0 : (~uint32_t(0) << (32 - prefix));
        network &= mask;
    } else {
        network = ipToUint32(cidrRange);
    }

    std::lock_guard<std::mutex> lock(mutex_);
    mappings_.push_back({network, mask, countryCode});
    logger_.debug("Added GeoIP mapping: {} -> {}", cidrRange, countryCode);
}

std::string GeoIPDatabase::lookupCountry(const std::string& ip) const {
    uint32_t addr = ipToUint32(ip);

    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& mapping : mappings_) {
        if ((addr & mapping.mask) == mapping.network) {
            return mapping.countryCode;
        }
    }
    return ""; // Unknown
}

void GeoIPDatabase::loadDefaultMappings() {
    // Pre-populate with example ranges
    addMapping("1.0.0.0/8", "AU");     // APNIC - Australia
    addMapping("2.0.0.0/8", "FR");     // RIPE NCC - France
    addMapping("5.0.0.0/8", "DE");     // RIPE NCC - Germany
    addMapping("8.8.8.0/24", "US");    // Google DNS - US
    addMapping("10.0.0.0/8", "XX");    // Private range
    addMapping("31.0.0.0/8", "RU");    // Russia
    addMapping("41.0.0.0/8", "ZA");    // Africa - South Africa
    addMapping("58.0.0.0/8", "CN");    // China
    addMapping("77.0.0.0/8", "GB");    // UK
    addMapping("91.0.0.0/8", "IR");    // Iran
    addMapping("103.0.0.0/8", "IN");   // India
    addMapping("172.16.0.0/12", "XX"); // Private range
    addMapping("192.168.0.0/16", "XX"); // Private range

    logger_.info("Loaded default GeoIP mappings");
}

// --- GeoBlocker ---

GeoBlocker::GeoBlocker()
    : database_(std::make_shared<GeoIPDatabase>())
    , logger_(Core::Logger::instance().getModuleLogger("GeoBlocker")) {
    logger_.info("GeoBlocker initialized with default database");
}

GeoBlocker::GeoBlocker(std::shared_ptr<GeoIPDatabase> db)
    : database_(std::move(db))
    , logger_(Core::Logger::instance().getModuleLogger("GeoBlocker")) {
    logger_.info("GeoBlocker initialized with custom database");
}

void GeoBlocker::setDatabase(std::shared_ptr<GeoIPDatabase> db) {
    std::lock_guard<std::mutex> lock(mutex_);
    database_ = std::move(db);
}

void GeoBlocker::addBlockedCountry(const std::string& code) {
    std::lock_guard<std::mutex> lock(mutex_);
    blockedCountries_.insert(code);
    logger_.info("Blocked country: {}", code);
}

void GeoBlocker::removeBlockedCountry(const std::string& code) {
    std::lock_guard<std::mutex> lock(mutex_);
    blockedCountries_.erase(code);
    logger_.info("Unblocked country: {}", code);
}

bool GeoBlocker::isBlocked(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!database_ || blockedCountries_.empty()) {
        return false;
    }

    std::string country = database_->lookupCountry(ip);
    if (country.empty()) {
        return false;
    }

    return blockedCountries_.count(country) > 0;
}

std::vector<std::string> GeoBlocker::getBlockedCountries() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return {blockedCountries_.begin(), blockedCountries_.end()};
}

} // namespace ThreatOne::Network
