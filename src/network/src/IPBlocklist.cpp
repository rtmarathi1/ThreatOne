#include "network/IPBlocklist.h"

#include <algorithm>
#include <sstream>
#include <stdexcept>

namespace ThreatOne::Network {

IPBlocklist::IPBlocklist()
    : logger_(Core::Logger::instance().getModuleLogger("IPBlocklist")) {
    logger_.info("IPBlocklist initialized");
}

uint32_t IPBlocklist::ipToUint32(const std::string& ip) {
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

bool IPBlocklist::isValidIP(const std::string& ip) {
    int dots = 0;
    int octet = 0;
    bool hasDigit = false;

    for (char c : ip) {
        if (c == '.') {
            if (!hasDigit || octet > 255) return false;
            dots++;
            octet = 0;
            hasDigit = false;
        } else if (c >= '0' && c <= '9') {
            octet = octet * 10 + (c - '0');
            hasDigit = true;
        } else {
            return false;
        }
    }
    return dots == 3 && hasDigit && octet <= 255;
}

void IPBlocklist::addIP(const std::string& ip) {
    if (!isValidIP(ip)) {
        logger_.warn("Invalid IP address: {}", ip);
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    uint32_t addr = ipToUint32(ip);
    blockedIPs_.push_back(addr);
    sortIPs();
    logger_.debug("Added IP to blocklist: {}", ip);
}

void IPBlocklist::removeIP(const std::string& ip) {
    if (!isValidIP(ip)) return;

    std::lock_guard<std::mutex> lock(mutex_);
    uint32_t addr = ipToUint32(ip);
    auto it = std::lower_bound(blockedIPs_.begin(), blockedIPs_.end(), addr);
    if (it != blockedIPs_.end() && *it == addr) {
        blockedIPs_.erase(it);
        logger_.debug("Removed IP from blocklist: {}", ip);
    }
}

void IPBlocklist::addRange(const std::string& cidr) {
    // Parse CIDR notation: "192.168.1.0/24"
    auto slashPos = cidr.find('/');
    if (slashPos == std::string::npos) {
        // Treat as single IP
        addIP(cidr);
        return;
    }

    std::string ipPart = cidr.substr(0, slashPos);
    int prefix = std::stoi(cidr.substr(slashPos + 1));

    if (prefix < 0 || prefix > 32 || !isValidIP(ipPart)) {
        logger_.warn("Invalid CIDR range: {}", cidr);
        return;
    }

    uint32_t network = ipToUint32(ipPart);
    uint32_t mask = (prefix == 0) ? 0 : (~uint32_t(0) << (32 - prefix));
    network &= mask; // Normalize network address

    std::lock_guard<std::mutex> lock(mutex_);
    blockedRanges_.push_back({network, mask});
    logger_.debug("Added CIDR range to blocklist: {}", cidr);
}

bool IPBlocklist::isBlocked(const std::string& ip) const {
    if (!isValidIP(ip)) return false;

    std::lock_guard<std::mutex> lock(mutex_);
    uint32_t addr = ipToUint32(ip);

    // Binary search in sorted IP list
    if (binarySearchIP(addr)) {
        return true;
    }

    // Check CIDR ranges
    for (const auto& range : blockedRanges_) {
        if ((addr & range.mask) == range.network) {
            return true;
        }
    }

    return false;
}

void IPBlocklist::importList(const std::vector<std::string>& ips) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& ip : ips) {
        if (isValidIP(ip)) {
            blockedIPs_.push_back(ipToUint32(ip));
        }
    }
    sortIPs();
    logger_.info("Imported {} IPs to blocklist", ips.size());
}

size_t IPBlocklist::getBlockedCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return blockedIPs_.size() + blockedRanges_.size();
}

void IPBlocklist::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    blockedIPs_.clear();
    blockedRanges_.clear();
    logger_.info("Blocklist cleared");
}

void IPBlocklist::sortIPs() {
    std::sort(blockedIPs_.begin(), blockedIPs_.end());
    // Remove duplicates
    blockedIPs_.erase(std::unique(blockedIPs_.begin(), blockedIPs_.end()), blockedIPs_.end());
}

bool IPBlocklist::binarySearchIP(uint32_t ip) const {
    return std::binary_search(blockedIPs_.begin(), blockedIPs_.end(), ip);
}

} // namespace ThreatOne::Network
