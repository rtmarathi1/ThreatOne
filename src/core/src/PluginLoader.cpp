#include "core/PluginLoader.h"
#include "core/Logger.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif
#include <algorithm>
#include <queue>
#include <set>

namespace ThreatOne::Core {

PluginLoader& PluginLoader::instance() {
    static PluginLoader instance;
    return instance;
}

PluginLoader::~PluginLoader() {
    shutdownAll();
}

void PluginLoader::addSearchPath(const std::filesystem::path& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    searchPaths_.push_back(path);
}

void PluginLoader::clearSearchPaths() {
    std::lock_guard<std::mutex> lock(mutex_);
    searchPaths_.clear();
}

const std::vector<std::filesystem::path>& PluginLoader::searchPaths() const {
    return searchPaths_;
}

Result<std::vector<std::string>> PluginLoader::discover() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> found;
    std::string ext = sharedLibExtension();

    for (const auto& searchPath : searchPaths_) {
        if (!std::filesystem::exists(searchPath)) continue;

        for (const auto& entry : std::filesystem::directory_iterator(searchPath)) {
            if (!entry.is_regular_file()) continue;
            auto filename = entry.path().filename().string();
            if (filename.size() > ext.size() &&
                filename.substr(filename.size() - ext.size()) == ext) {
                found.push_back(entry.path().stem().string());
            }
        }
    }

    return Result<std::vector<std::string>>::ok(std::move(found));
}

Result<void> PluginLoader::load(const std::string& pluginName) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (plugins_.find(pluginName) != plugins_.end()) {
        return Result<void>::err(
            Error("Plugin already loaded: " + pluginName,
                  ErrorCategory::Plugin,
                  ErrorSeverity::Warning));
    }

    // Search for the plugin in search paths
    std::string ext = sharedLibExtension();
    std::filesystem::path pluginPath;

    for (const auto& searchPath : searchPaths_) {
        auto candidate = searchPath / (pluginName + ext);
        if (std::filesystem::exists(candidate)) {
            pluginPath = candidate;
            break;
        }
        // Also try with "lib" prefix
        candidate = searchPath / ("lib" + pluginName + ext);
        if (std::filesystem::exists(candidate)) {
            pluginPath = candidate;
            break;
        }
    }

    if (pluginPath.empty()) {
        return Result<void>::err(
            Error("Plugin not found: " + pluginName,
                  ErrorCategory::Plugin,
                  ErrorSeverity::Error));
    }

    // Load the shared library
#ifdef _WIN32
    void* handle = reinterpret_cast<void*>(LoadLibraryA(pluginPath.string().c_str()));
    if (!handle) {
        return Result<void>::err(
            Error("Failed to load plugin: " + pluginName + " (error " + std::to_string(GetLastError()) + ")",
                  ErrorCategory::Plugin,
                  ErrorSeverity::Error));
    }

    // Look up factory function
    auto createFn = reinterpret_cast<PluginCreateFn>(
        GetProcAddress(reinterpret_cast<HMODULE>(handle), "threatone_plugin_create"));
    auto destroyFn = reinterpret_cast<PluginDestroyFn>(
        GetProcAddress(reinterpret_cast<HMODULE>(handle), "threatone_plugin_destroy"));

    if (!createFn || !destroyFn) {
        FreeLibrary(reinterpret_cast<HMODULE>(handle));
        return Result<void>::err(
            Error("Plugin missing entry points: " + pluginName,
                  ErrorCategory::Plugin,
                  ErrorSeverity::Error));
    }

    // Create plugin instance
    IPlugin* rawPlugin = createFn();
    if (!rawPlugin) {
        FreeLibrary(reinterpret_cast<HMODULE>(handle));
        return Result<void>::err(
            Error("Plugin factory returned null: " + pluginName,
                  ErrorCategory::Plugin,
                  ErrorSeverity::Error));
    }
#else
    void* handle = dlopen(pluginPath.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        return Result<void>::err(
            Error(std::string("Failed to load plugin: ") + dlerror(),
                  ErrorCategory::Plugin,
                  ErrorSeverity::Error));
    }

    // Look up factory function
    auto createFn = reinterpret_cast<PluginCreateFn>(dlsym(handle, "threatone_plugin_create"));
    auto destroyFn = reinterpret_cast<PluginDestroyFn>(dlsym(handle, "threatone_plugin_destroy"));

    if (!createFn || !destroyFn) {
        dlclose(handle);
        return Result<void>::err(
            Error("Plugin missing entry points: " + pluginName,
                  ErrorCategory::Plugin,
                  ErrorSeverity::Error));
    }

    // Create plugin instance
    IPlugin* rawPlugin = createFn();
    if (!rawPlugin) {
        dlclose(handle);
        return Result<void>::err(
            Error("Plugin factory returned null: " + pluginName,
                  ErrorCategory::Plugin,
                  ErrorSeverity::Error));
    }
#endif

    auto loaded = std::make_unique<LoadedPlugin>();
    loaded->name = rawPlugin->name();
    loaded->path = pluginPath;
    loaded->instance = std::unique_ptr<IPlugin, void(*)(IPlugin*)>(rawPlugin, destroyFn);
    loaded->handle = handle;
    loaded->state = PluginState::Loaded;
    loaded->metadata = rawPlugin->metadata();

    plugins_[loaded->name] = std::move(loaded);
    return Result<void>::ok();
}

Result<void> PluginLoader::loadFromPath(const std::filesystem::path& path) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!std::filesystem::exists(path)) {
        return Result<void>::err(
            Error("Plugin file not found: " + path.string(),
                  ErrorCategory::Plugin,
                  ErrorSeverity::Error));
    }

#ifdef _WIN32
    void* handle = reinterpret_cast<void*>(LoadLibraryA(path.string().c_str()));
    if (!handle) {
        return Result<void>::err(
            Error("Failed to load plugin: " + path.string() + " (error " + std::to_string(GetLastError()) + ")",
                  ErrorCategory::Plugin,
                  ErrorSeverity::Error));
    }

    auto createFn = reinterpret_cast<PluginCreateFn>(
        GetProcAddress(reinterpret_cast<HMODULE>(handle), "threatone_plugin_create"));
    auto destroyFn = reinterpret_cast<PluginDestroyFn>(
        GetProcAddress(reinterpret_cast<HMODULE>(handle), "threatone_plugin_destroy"));

    if (!createFn || !destroyFn) {
        FreeLibrary(reinterpret_cast<HMODULE>(handle));
        return Result<void>::err(
            Error("Plugin missing entry points: " + path.string(),
                  ErrorCategory::Plugin,
                  ErrorSeverity::Error));
    }

    IPlugin* rawPlugin = createFn();
    if (!rawPlugin) {
        FreeLibrary(reinterpret_cast<HMODULE>(handle));
        return Result<void>::err(
            Error("Plugin factory returned null: " + path.string(),
                  ErrorCategory::Plugin,
                  ErrorSeverity::Error));
    }
#else
    void* handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        return Result<void>::err(
            Error(std::string("Failed to load plugin: ") + dlerror(),
                  ErrorCategory::Plugin,
                  ErrorSeverity::Error));
    }

    auto createFn = reinterpret_cast<PluginCreateFn>(dlsym(handle, "threatone_plugin_create"));
    auto destroyFn = reinterpret_cast<PluginDestroyFn>(dlsym(handle, "threatone_plugin_destroy"));

    if (!createFn || !destroyFn) {
        dlclose(handle);
        return Result<void>::err(
            Error("Plugin missing entry points: " + path.string(),
                  ErrorCategory::Plugin,
                  ErrorSeverity::Error));
    }

    IPlugin* rawPlugin = createFn();
    if (!rawPlugin) {
        dlclose(handle);
        return Result<void>::err(
            Error("Plugin factory returned null: " + path.string(),
                  ErrorCategory::Plugin,
                  ErrorSeverity::Error));
    }
#endif

    auto loaded = std::make_unique<LoadedPlugin>();
    loaded->name = rawPlugin->name();
    loaded->path = path;
    loaded->instance = std::unique_ptr<IPlugin, void(*)(IPlugin*)>(rawPlugin, destroyFn);
    loaded->handle = handle;
    loaded->state = PluginState::Loaded;
    loaded->metadata = rawPlugin->metadata();

    if (plugins_.find(loaded->name) != plugins_.end()) {
#ifdef _WIN32
        FreeLibrary(reinterpret_cast<HMODULE>(handle));
#else
        dlclose(handle);
#endif
        return Result<void>::err(
            Error("Plugin already loaded: " + loaded->name,
                  ErrorCategory::Plugin,
                  ErrorSeverity::Warning));
    }

    plugins_[loaded->name] = std::move(loaded);
    return Result<void>::ok();
}

Result<void> PluginLoader::unload(const std::string& pluginName) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = plugins_.find(pluginName);
    if (it == plugins_.end()) {
        return Result<void>::err(
            Error("Plugin not found: " + pluginName,
                  ErrorCategory::Plugin,
                  ErrorSeverity::Warning));
    }

    auto& plugin = it->second;

    // Shutdown if running
    if (plugin->state == PluginState::Running ||
        plugin->state == PluginState::Initialized) {
        plugin->instance->shutdown();
    }

    // Close the shared library
    if (plugin->handle) {
        plugin->instance.reset();
#ifdef _WIN32
        FreeLibrary(reinterpret_cast<HMODULE>(plugin->handle));
#else
        dlclose(plugin->handle);
#endif
    }

    plugins_.erase(it);
    return Result<void>::ok();
}

Result<void> PluginLoader::initializeAll() {
    auto orderResult = resolveDependencyOrder();
    if (!orderResult) {
        return Result<void>::err(orderResult.error());
    }

    const auto& order = orderResult.value();

    for (const auto& name : order) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = plugins_.find(name);
        if (it == plugins_.end()) continue;

        auto& plugin = it->second;
        if (plugin->state != PluginState::Loaded) continue;

        auto result = plugin->instance->initialize();
        if (!result) {
            plugin->state = PluginState::Error;
            return Result<void>::err(
                Error("Failed to initialize plugin: " + name + " - " +
                      result.error().message(),
                      ErrorCategory::Plugin,
                      ErrorSeverity::Error));
        }
        plugin->state = PluginState::Initialized;
    }

    return Result<void>::ok();
}

void PluginLoader::shutdownAll() {
    // Get reverse dependency order
    auto orderResult = resolveDependencyOrder();
    std::vector<std::string> order;

    if (orderResult) {
        order = orderResult.value();
        std::reverse(order.begin(), order.end());
    } else {
        // If dependency resolution fails, just shut down in arbitrary order
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [name, plugin] : plugins_) {
            order.push_back(name);
        }
    }

    for (const auto& name : order) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = plugins_.find(name);
        if (it == plugins_.end()) continue;

        auto& plugin = it->second;
        if (plugin->state == PluginState::Running ||
            plugin->state == PluginState::Initialized) {
            plugin->instance->shutdown();
            plugin->state = PluginState::Stopped;
        }
    }

    // Close all library handles
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [name, plugin] : plugins_) {
        if (plugin->handle) {
            plugin->instance.reset();
#ifdef _WIN32
            FreeLibrary(reinterpret_cast<HMODULE>(plugin->handle));
#else
            dlclose(plugin->handle);
#endif
            plugin->handle = nullptr;
        }
    }
    plugins_.clear();
}

IPlugin* PluginLoader::getPlugin(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = plugins_.find(name);
    if (it == plugins_.end()) return nullptr;
    return it->second->instance.get();
}

std::vector<std::string> PluginLoader::loadedPlugins() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> names;
    names.reserve(plugins_.size());
    for (const auto& [name, plugin] : plugins_) {
        names.push_back(name);
    }
    return names;
}

bool PluginLoader::isLoaded(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return plugins_.find(name) != plugins_.end();
}

PluginState PluginLoader::getState(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = plugins_.find(name);
    if (it == plugins_.end()) return PluginState::Unloaded;
    return it->second->state;
}

Result<std::vector<std::string>> PluginLoader::resolveDependencyOrder() const {
    std::lock_guard<std::mutex> lock(mutex_);

    // Build dependency graph
    std::unordered_map<std::string, std::vector<std::string>> graph;
    for (const auto& [name, plugin] : plugins_) {
        graph[name] = plugin->instance->dependencies();
    }

    return topologicalSort(graph);
}

Result<std::vector<std::string>> PluginLoader::topologicalSort(
    const std::unordered_map<std::string, std::vector<std::string>>& graph) const {

    // NOTE: This topological sort is O(V * E) due to the inner scan of all graph edges
    // when decrementing in-degrees. For the expected plugin count (< 50), this is
    // acceptable. For large plugin ecosystems, consider building an adjacency list of
    // dependents (reverse edges) for O(V + E) BFS. This is a known Phase 1 simplification.

    // Calculate in-degrees (number of dependencies each node has within the graph)
    std::unordered_map<std::string, size_t> inDegree;
    for (const auto& [node, deps] : graph) {
        if (inDegree.find(node) == inDegree.end()) {
            inDegree[node] = 0;
        }
        for (const auto& dep : deps) {
            // Only count edges to nodes that exist in our graph
            if (graph.find(dep) != graph.end()) {
                inDegree[node]++;
            }
        }
    }

    // Start with nodes that have no dependencies (in-degree 0)
    std::queue<std::string> ready;
    for (const auto& [node, degree] : inDegree) {
        if (degree == 0) {
            ready.push(node);
        }
    }

    std::vector<std::string> result;
    while (!ready.empty()) {
        auto current = ready.front();
        ready.pop();
        result.push_back(current);

        // Reduce in-degree of nodes that depend on current
        for (const auto& [node, deps] : graph) {
            for (const auto& dep : deps) {
                if (dep == current && graph.find(dep) != graph.end()) {
                    inDegree[node]--;
                    if (inDegree[node] == 0) {
                        ready.push(node);
                    }
                }
            }
        }
    }

    if (result.size() != graph.size()) {
        return Result<std::vector<std::string>>::err(
            Error("Circular dependency detected in plugins",
                  ErrorCategory::Plugin,
                  ErrorSeverity::Error));
    }

    return Result<std::vector<std::string>>::ok(std::move(result));
}

std::string PluginLoader::sharedLibExtension() {
#if THREATONE_PLATFORM_WINDOWS
    return ".dll";
#elif THREATONE_PLATFORM_MACOS
    return ".dylib";
#else
    return ".so";
#endif
}

} // namespace ThreatOne::Core
