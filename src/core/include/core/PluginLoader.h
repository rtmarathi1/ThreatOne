#pragma once

// ThreatOne Core - Plugin Loader
// Discovers, loads (via dlopen), unloads plugins, and resolves dependencies

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <filesystem>
#include <mutex>

#include "core/Types.h"
#include "core/Error.h"
#include "core/PluginInterface.h"

namespace ThreatOne::Core {

// Information about a loaded plugin
struct LoadedPlugin {
    std::string name;
    std::filesystem::path path;
    std::unique_ptr<IPlugin, void(*)(IPlugin*)> instance{nullptr, nullptr};
    void* handle = nullptr; // dlopen handle
    PluginState state = PluginState::Unloaded;
    PluginMetadata metadata;

    LoadedPlugin() = default;
    LoadedPlugin(LoadedPlugin&&) = default;
    LoadedPlugin& operator=(LoadedPlugin&&) = default;
    LoadedPlugin(const LoadedPlugin&) = delete;
    LoadedPlugin& operator=(const LoadedPlugin&) = delete;
};

class PluginLoader {
public:
    // Singleton access
    static PluginLoader& instance();

    // Set plugin search directories
    void addSearchPath(const std::filesystem::path& path);
    void clearSearchPaths();
    [[nodiscard]] const std::vector<std::filesystem::path>& searchPaths() const;

    // Discover plugins in search paths
    [[nodiscard]] Result<std::vector<std::string>> discover();

    // Load a single plugin by name or path
    [[nodiscard]] Result<void> load(const std::string& pluginName);
    [[nodiscard]] Result<void> loadFromPath(const std::filesystem::path& path);

    // Unload a plugin
    [[nodiscard]] Result<void> unload(const std::string& pluginName);

    // Initialize all loaded plugins (respecting dependency order)
    [[nodiscard]] Result<void> initializeAll();

    // Shutdown all plugins (reverse dependency order)
    void shutdownAll();

    // Get a loaded plugin by name
    [[nodiscard]] IPlugin* getPlugin(const std::string& name) const;

    // Get all loaded plugin names
    [[nodiscard]] std::vector<std::string> loadedPlugins() const;

    // Check if a plugin is loaded
    [[nodiscard]] bool isLoaded(const std::string& name) const;

    // Get plugin state
    [[nodiscard]] PluginState getState(const std::string& name) const;

    // Resolve dependency order (topological sort)
    [[nodiscard]] Result<std::vector<std::string>> resolveDependencyOrder() const;

    // Non-copyable, non-movable
    PluginLoader(const PluginLoader&) = delete;
    PluginLoader& operator=(const PluginLoader&) = delete;
    PluginLoader(PluginLoader&&) = delete;
    PluginLoader& operator=(PluginLoader&&) = delete;

private:
    PluginLoader() = default;
    ~PluginLoader();

    // Platform-specific library file extension
    [[nodiscard]] static std::string sharedLibExtension();

    // Topological sort helper
    [[nodiscard]] Result<std::vector<std::string>> topologicalSort(
        const std::unordered_map<std::string, std::vector<std::string>>& graph) const;

    mutable std::mutex mutex_;
    std::vector<std::filesystem::path> searchPaths_;
    std::unordered_map<std::string, std::unique_ptr<LoadedPlugin>> plugins_;
};

} // namespace ThreatOne::Core
