#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <mutex>

#include "core/Logger.h"

namespace ThreatOne::Network {

class IPBlocklist {
public:
    IPBlocklist();

    void addIP(const std::string& ip);
    void removeIP(const std::string& ip);
    void addRange(const std::string& cidr);
    bool isBlocked(const std::string& ip) const;
    void importList(const std::vector<std::string>& ips);
    size_t getBlockedCount() const;
    void clear();

private:
    static uint32_t ipToUint32(const std::string& ip);
    static bool isValidIP(const std::string& ip);

    struct CIDRRange {
        uint32_t network;
        uint32_t mask;
    };

    mutable std::mutex mutex_;
    std::vector<uint32_t> blockedIPs_;       // Sorted for binary search
    std::vector<CIDRRange> blockedRanges_;
    Core::ModuleLogger logger_;

    void sortIPs();
    bool binarySearchIP(uint32_t ip) const;
};

} // namespace ThreatOne::Network
