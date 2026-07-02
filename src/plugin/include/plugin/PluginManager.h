#pragma once

// ThreatOne Plugin - Plugin Manager Implementation
// Full lifecycle, dependency resolution, permissions, marketplace

#include "plugin/IPluginManager.h"
#include "plugin/PluginSDK.h"
#include "plugin/PluginSandbox.h"
#include "plugin/PluginMarketplace.h"
#include "plugin/DependencyResolver.h"
#include "plugin/PluginPermissions.h"
#include "plugin/PluginVersionManager.h"
#include "core/Logger.h"

#include <mutex>
#include <unordered_map>
#include <map>
#include <set>
#include <optional>
#include <memory>
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

    // Access to sub-components
    [[nodiscard]] PluginSDK& getSDK() { return *sdk_; }
    [[nodiscard]] PluginSandbox& getSandbox() { return *sandbox_; }
    [[nodiscard]] PluginMarketplace& getMarketplaceManager() { return *marketplace_; }
    [[nodiscard]] DependencyResolver& getDependencyResolver() { return *dependencyResolver_; }
    [[nodiscard]] PluginPermissions& getPermissionsManager() { return *permissions_; }
    [[nodiscard]] PluginVersionManager& getVersionManager() { return *versionManager_; }

private:
    std::string generateId();

    // Sub-components
    std::shared_ptr<PluginSDK> sdk_;
    std::shared_ptr<PluginSandbox> sandbox_;
    std::shared_ptr<PluginMarketplace> marketplace_;
    std::shared_ptr<DependencyResolver> dependencyResolver_;
    std::shared_ptr<PluginPermissions> permissions_;
    std::shared_ptr<PluginVersionManager> versionManager_;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, PluginInfo> plugins_;
    std::unordered_map<std::string, std::set<PluginPermission>> permissionSets_;
    std::unordered_map<std::string, PluginManifest> manifests_;
    std::multimap<std::string, PluginHook> hooks_;  // eventType -> hook
    int nextId_ = 1;
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Plugin
