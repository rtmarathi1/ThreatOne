#pragma once

#include <string>
#include <vector>
#include <unordered_set>
#include <mutex>

#include "core/Logger.h"

namespace ThreatOne::Network {

class NetworkIsolation {
public:
    NetworkIsolation();

    void enableIsolation(const std::vector<std::string>& managementIPs);
    void disableIsolation();
    bool isIsolated() const;
    bool isAllowed(const std::string& ip) const;
    std::vector<std::string> getManagementIPs() const;

private:
    mutable std::mutex mutex_;
    bool isolated_ = false;
    std::unordered_set<std::string> managementIPs_;
    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Network
