#include "network/ApplicationControl.h"
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace ThreatOne::Network {

ApplicationControl::ApplicationControl()
    : logger_(Core::Logger::instance().getModuleLogger("ApplicationControl")) {
    logger_.info("ApplicationControl initialized (default policy: allow)");
}

void ApplicationControl::allowApplication(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    policies_[path] = AppPolicy::Allow;
    logger_.info("Application allowed: {}", path);
}

void ApplicationControl::denyApplication(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    policies_[path] = AppPolicy::Deny;
    logger_.info("Application denied: {}", path);
}

void ApplicationControl::removeApplication(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    policies_.erase(path);
    logger_.info("Application policy removed: {}", path);
}

bool ApplicationControl::isAllowed(const std::string& appPath) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = policies_.find(appPath);
    if (it == policies_.end()) {
        return defaultPolicy_ == AppPolicy::Allow;
    }
    return it->second == AppPolicy::Allow;
}

std::optional<AppPolicy> ApplicationControl::getPolicy(const std::string& appPath) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = policies_.find(appPath);
    if (it == policies_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<std::pair<std::string, AppPolicy>> ApplicationControl::getAllPolicies() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::pair<std::string, AppPolicy>> result;
    result.reserve(policies_.size());
    for (const auto& [path, policy] : policies_) {
        result.emplace_back(path, policy);
    }
    return result;
}

void ApplicationControl::setDefaultPolicy(AppPolicy policy) {
    std::lock_guard<std::mutex> lock(mutex_);
    defaultPolicy_ = policy;
    logger_.info("Default policy set to: {}",
                 policy == AppPolicy::Allow ? "allow" : "deny");
}

AppPolicy ApplicationControl::getDefaultPolicy() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return defaultPolicy_;
}

} // namespace ThreatOne::Network
