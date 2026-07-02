#include "plugin/PluginSDK.h"

#include <algorithm>

namespace ThreatOne::Plugin {

PluginSDK::PluginSDK()
    : logger_("PluginSDK") {
    logger_.info("PluginSDK initialized");
}

PluginSDKContext PluginSDK::createContext(const std::string& pluginId, const std::set<PluginPermission>& permissions) {
    std::lock_guard<std::mutex> lock(mutex_);

    PluginSDKContext context;
    context.pluginId = pluginId;
    context.permissions = permissions;
    context.apiVersion = "1.0.0";
    context.dataDirectory = "/data/plugins/" + pluginId;

    contexts_[pluginId] = context;
    logger_.info("Created SDK context for plugin: {}", pluginId);
    return context;
}

PluginSDKContext PluginSDK::getContext(const std::string& pluginId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = contexts_.find(pluginId);
    if (it == contexts_.end()) {
        return {};
    }
    return it->second;
}

bool PluginSDK::removeContext(const std::string& pluginId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = contexts_.find(pluginId);
    if (it == contexts_.end()) {
        return false;
    }

    contexts_.erase(it);
    logger_.info("Removed SDK context for plugin: {}", pluginId);
    return true;
}

bool PluginSDK::hasContext(const std::string& pluginId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return contexts_.count(pluginId) > 0;
}

void PluginSDK::registerHookPoint(const std::string& eventType, const PluginHook& hook) {
    std::lock_guard<std::mutex> lock(mutex_);
    hooks_.emplace(eventType, hook);
    logger_.info("Registered hook point: event={}, name={}", eventType, hook.name);
}

void PluginSDK::unregisterHookPoints(const std::string& pluginId) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Remove all hooks where the hook name contains the plugin ID prefix
    // In practice, hooks are identified by name patterns
    for (auto it = hooks_.begin(); it != hooks_.end();) {
        if (it->second.name.find(pluginId) != std::string::npos) {
            it = hooks_.erase(it);
        } else {
            ++it;
        }
    }
    logger_.info("Unregistered hook points for plugin: {}", pluginId);
}

std::vector<PluginHook> PluginSDK::getHooksForEvent(const std::string& eventType) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<PluginHook> result;
    auto range = hooks_.equal_range(eventType);
    for (auto it = range.first; it != range.second; ++it) {
        result.push_back(it->second);
    }

    // Sort by priority descending
    std::sort(result.begin(), result.end(),
              [](const PluginHook& a, const PluginHook& b) {
                  return a.priority > b.priority;
              });

    return result;
}

std::vector<std::string> PluginSDK::getRegisteredEventTypes() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::set<std::string> types;
    for (const auto& [eventType, hook] : hooks_) {
        types.insert(eventType);
    }
    return std::vector<std::string>(types.begin(), types.end());
}

void PluginSDK::registerService(const SDKService& service) {
    std::lock_guard<std::mutex> lock(mutex_);
    services_[service.name] = service;
    logger_.info("Registered SDK service: {}", service.name);
}

std::vector<SDKService> PluginSDK::getAvailableServices() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<SDKService> result;
    for (const auto& [name, service] : services_) {
        if (service.available) {
            result.push_back(service);
        }
    }
    return result;
}

bool PluginSDK::isServiceAvailable(const std::string& serviceName) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = services_.find(serviceName);
    if (it == services_.end()) {
        return false;
    }
    return it->second.available;
}

size_t PluginSDK::getContextCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return contexts_.size();
}

} // namespace ThreatOne::Plugin
