#pragma once

#include "plugin/IPluginManager.h"
#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>
#include <set>
#include <functional>

namespace ThreatOne::Plugin {

struct SDKService {
    std::string name;
    std::string version;
    std::string description;
    bool available = true;
};

class PluginSDK {
public:
    PluginSDK();
    ~PluginSDK() = default;

    // SDK context management
    PluginSDKContext createContext(const std::string& pluginId, const std::set<PluginPermission>& permissions);
    [[nodiscard]] PluginSDKContext getContext(const std::string& pluginId) const;
    bool removeContext(const std::string& pluginId);
    [[nodiscard]] bool hasContext(const std::string& pluginId) const;

    // Hook point management
    void registerHookPoint(const std::string& eventType, const PluginHook& hook);
    void unregisterHookPoints(const std::string& pluginId);
    [[nodiscard]] std::vector<PluginHook> getHooksForEvent(const std::string& eventType) const;
    [[nodiscard]] std::vector<std::string> getRegisteredEventTypes() const;

    // Service registration
    void registerService(const SDKService& service);
    [[nodiscard]] std::vector<SDKService> getAvailableServices() const;
    [[nodiscard]] bool isServiceAvailable(const std::string& serviceName) const;

    // API version
    [[nodiscard]] std::string getApiVersion() const { return "1.0.0"; }
    [[nodiscard]] size_t getContextCount() const;

private:
    mutable std::mutex mutex_;
    std::map<std::string, PluginSDKContext> contexts_;
    std::multimap<std::string, PluginHook> hooks_;  // eventType -> hook
    std::map<std::string, SDKService> services_;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Plugin
