#pragma once

// ThreatOne Plugin - Plugin Manager Implementation
// Full lifecycle, dependency resolution, permissions, marketplace

#include "plugin/IPluginManager.h"
#include "core/Logger.h"

#include <mutex>
#include <unordered_map>
#include <map>
#include <set>
#include <optional>
#include <string>
#include <vector>

namespace ThreatOne::Plugin {

class PluginManager : public IPluginManager {
public:
    PluginManager();
    ~PluginManager() override = default;

    // Plugin lifecycle
    bool loadPlugin(const std::string& path) override;
    bool unloadPlugin(const std::string& pluginId) override;
    bool reloadPlugin(const std::string& pluginId) override;
    std::vector<PluginInfo> getPlugins() override;
    bool enablePlugin(const std::string& pluginId) override;
    bool disablePlugin(const std::string& pluginId) override;
    std::optional<PluginState> getPluginState(const std::string& pluginId) override;

    // Permission management
    bool setPluginPermissions(const std::string& pluginId,
                              const std::vector<PluginPermission>& permissions) override;
    std::vector<PluginPermission> getPluginPermissions(const std::string& pluginId) override;
    bool checkPermission(const std::string& pluginId, PluginPermission permission) override;

    // Dependency resolution
    std::vector<std::string> resolveDependencies(const std::string& pluginId) override;

    // Hooks
    std::vector<PluginHook> getPluginHooks(const std::string& eventType) override;

    // Marketplace
    std::vector<MarketplaceEntry> getMarketplace() override;
    std::vector<MarketplaceEntry> searchMarketplace(const std::string& query) override;
    std::optional<MarketplaceEntry> getMarketplaceEntry(const std::string& pluginId) override;
    bool checkCompatibility(const std::string& pluginId, const std::string& version) override;
    bool installFromMarketplace(const std::string& pluginId) override;

    // Non-interface helpers for testing
    void addMarketplaceEntry(const MarketplaceEntry& entry);
    void registerManifest(const PluginManifest& manifest);

private:
    std::string generateId();

    mutable std::mutex mutex_;
    std::unordered_map<std::string, PluginInfo> plugins_;
    std::unordered_map<std::string, std::set<PluginPermission>> permissions_;
    std::unordered_map<std::string, PluginManifest> manifests_;
    std::vector<MarketplaceEntry> marketplace_;
    std::multimap<std::string, PluginHook> hooks_;  // eventType -> hook
    int nextId_ = 1;
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Plugin
