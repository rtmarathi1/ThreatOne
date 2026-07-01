#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <mutex>

#include "core/Logger.h"

namespace ThreatOne::Network {

enum class AppPolicy {
    Allow,
    Deny
};

class ApplicationControl {
public:
    ApplicationControl();

    void allowApplication(const std::string& path);
    void denyApplication(const std::string& path);
    void removeApplication(const std::string& path);
    bool isAllowed(const std::string& appPath) const;
    std::optional<AppPolicy> getPolicy(const std::string& appPath) const;
    std::vector<std::pair<std::string, AppPolicy>> getAllPolicies() const;

    void setDefaultPolicy(AppPolicy policy);
    AppPolicy getDefaultPolicy() const;

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, AppPolicy> policies_;
    AppPolicy defaultPolicy_ = AppPolicy::Allow;
    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Network
