#pragma once

// ThreatOne Plugin - Plugin Manager Interface
// Plugin lifecycle management, dependency resolution, marketplace, permissions

#include <string>
#include <vector>
#include <set>
#include <optional>
#include <cstdint>

namespace ThreatOne::Plugin {

enum class PluginState {
    Unloaded,
    Loaded,
    Enabled,
    Disabled,
    Error
};

enum class PluginPermission {
    NetworkAccess,
    FileRead,
    FileWrite,
    APIAccess,
    SystemInfo,
    ProcessControl
};

struct PluginHook {
    std::string name;
    std::string eventType;
    int priority = 0;
};

struct PluginSDKContext {
    std::string pluginId;
    std::set<PluginPermission> permissions;
    std::string apiVersion;
    std::string dataDirectory;
};

struct PluginDependency {
    std::string pluginId;
    std::string minVersion;
    bool required = true;
};

struct PluginManifest {
    std::string id;
    std::string name;
    std::string version;
    std::string author;
    std::string description;
    std::vector<PluginDependency> dependencies;
    std::vector<PluginPermission> requiredPermissions;
    std::vector<PluginHook> hooks;
    std::string entryPoint;
};

struct PluginInfo {
    std::string id;
    std::string name;
    std::string version;
    std::string author;
    std::string description;
    bool enabled = false;
    bool loaded = false;
    PluginState state = PluginState::Unloaded;
};

struct MarketplaceEntry {
    std::string id;
    std::string name;
    std::string version;
    std::string author;
    std::string description;
    uint64_t downloads = 0;
    double rating = 0.0;
    std::vector<std::string> compatibleVersions;
};

class IPluginManager {
public:
    virtual ~IPluginManager() = default;

    // Plugin lifecycle
    virtual bool loadPlugin(const std::string& path) = 0;
    virtual bool unloadPlugin(const std::string& pluginId) = 0;
    virtual bool reloadPlugin(const std::string& pluginId) = 0;
    virtual std::vector<PluginInfo> getPlugins() = 0;
    virtual bool enablePlugin(const std::string& pluginId) = 0;
    virtual bool disablePlugin(const std::string& pluginId) = 0;
    virtual std::optional<PluginState> getPluginState(const std::string& pluginId) = 0;

    // Permission management
    virtual bool setPluginPermissions(const std::string& pluginId,
                                      const std::vector<PluginPermission>& permissions) = 0;
    virtual std::vector<PluginPermission> getPluginPermissions(const std::string& pluginId) = 0;
    virtual bool checkPermission(const std::string& pluginId, PluginPermission permission) = 0;

    // Dependency resolution
    virtual std::vector<std::string> resolveDependencies(const std::string& pluginId) = 0;

    // Hooks
    virtual std::vector<PluginHook> getPluginHooks(const std::string& eventType) = 0;

    // Marketplace
    virtual std::vector<MarketplaceEntry> getMarketplace() = 0;
    virtual std::vector<MarketplaceEntry> searchMarketplace(const std::string& query) = 0;
    virtual std::optional<MarketplaceEntry> getMarketplaceEntry(const std::string& pluginId) = 0;
    virtual bool checkCompatibility(const std::string& pluginId, const std::string& version) = 0;
    virtual bool installFromMarketplace(const std::string& pluginId) = 0;
};

} // namespace ThreatOne::Plugin
