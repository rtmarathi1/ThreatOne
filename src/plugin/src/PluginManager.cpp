#include "plugin/PluginManager.h"

#include <algorithm>
#include <sstream>
#include <queue>
#include <unordered_set>

namespace ThreatOne::Plugin {

PluginManager::PluginManager()
    : logger_("PluginManager") {
    logger_.info("Plugin Manager initialized");
}

std::string PluginManager::generateId() {
    std::ostringstream oss;
    oss << "PLG-" << nextId_;
    ++nextId_;
    return oss.str();
}

bool PluginManager::loadPlugin(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (path.empty()) {
        logger_.error("Cannot load plugin: empty path");
        return false;
    }

    // Extract plugin ID from path (last component without extension)
    std::string pluginId;
    auto lastSlash = path.rfind('/');
    auto lastDot = path.rfind('.');
    if (lastSlash != std::string::npos) {
        pluginId = path.substr(lastSlash + 1);
    } else {
        pluginId = path;
    }
    if (lastDot != std::string::npos && lastDot > (lastSlash != std::string::npos ? lastSlash : 0)) {
        pluginId = pluginId.substr(0, pluginId.rfind('.'));
    }

    // If manifest exists, use manifest ID
    auto manifestIt = manifests_.find(pluginId);
    if (manifestIt != manifests_.end()) {
        pluginId = manifestIt->second.id;
    }

    // Check if already loaded
    auto existingIt = plugins_.find(pluginId);
    if (existingIt != plugins_.end() && existingIt->second.state == PluginState::Loaded) {
        logger_.warn("Plugin already loaded: {}", pluginId);
        return false;
    }

    // Create plugin info
    PluginInfo info;
    info.id = pluginId;
    info.loaded = true;
    info.enabled = false;
    info.state = PluginState::Loaded;

    // Populate from manifest if available
    if (manifestIt != manifests_.end()) {
        info.name = manifestIt->second.name;
        info.version = manifestIt->second.version;
        info.author = manifestIt->second.author;
        info.description = manifestIt->second.description;

        // Register hooks from manifest
        for (const auto& hook : manifestIt->second.hooks) {
            hooks_.emplace(hook.eventType, hook);
        }
    } else {
        info.name = pluginId;
        info.version = "1.0.0";
    }

    plugins_[pluginId] = info;
    logger_.info("Loaded plugin: {} ({})", pluginId, path);
    return true;
}

bool PluginManager::unloadPlugin(const std::string& pluginId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = plugins_.find(pluginId);
    if (it == plugins_.end()) {
        logger_.error("Cannot unload plugin: {} not found", pluginId);
        return false;
    }

    if (it->second.state == PluginState::Unloaded) {
        logger_.warn("Plugin already unloaded: {}", pluginId);
        return false;
    }

    // Check if other loaded plugins depend on this one
    for (const auto& [id, manifest] : manifests_) {
        if (id == pluginId) continue;
        auto plugIt = plugins_.find(id);
        if (plugIt == plugins_.end() || plugIt->second.state == PluginState::Unloaded) continue;

        for (const auto& dep : manifest.dependencies) {
            if (dep.pluginId == pluginId && dep.required) {
                logger_.error("Cannot unload plugin {}: required by {}", pluginId, id);
                return false;
            }
        }
    }

    // Remove hooks associated with this plugin
    if (manifests_.count(pluginId)) {
        for (const auto& hook : manifests_[pluginId].hooks) {
            auto range = hooks_.equal_range(hook.eventType);
            for (auto hookIt = range.first; hookIt != range.second;) {
                if (hookIt->second.name == hook.name) {
                    hookIt = hooks_.erase(hookIt);
                } else {
                    ++hookIt;
                }
            }
        }
    }

    it->second.state = PluginState::Unloaded;
    it->second.loaded = false;
    it->second.enabled = false;
    logger_.info("Unloaded plugin: {}", pluginId);
    return true;
}

bool PluginManager::reloadPlugin(const std::string& pluginId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = plugins_.find(pluginId);
    if (it == plugins_.end()) {
        logger_.error("Cannot reload plugin: {} not found", pluginId);
        return false;
    }

    std::string path = pluginId;

    // Unload inline (same logic as unloadPlugin but without acquiring mutex)
    if (it->second.state == PluginState::Unloaded) {
        logger_.warn("Plugin already unloaded: {}", pluginId);
        return false;
    }

    // Check if other loaded plugins depend on this one
    for (const auto& [id, manifest] : manifests_) {
        if (id == pluginId) continue;
        auto plugIt = plugins_.find(id);
        if (plugIt == plugins_.end() || plugIt->second.state == PluginState::Unloaded) continue;

        for (const auto& dep : manifest.dependencies) {
            if (dep.pluginId == pluginId && dep.required) {
                logger_.error("Cannot reload plugin {}: required by {}", pluginId, id);
                return false;
            }
        }
    }

    // Remove hooks associated with this plugin
    if (manifests_.count(pluginId)) {
        for (const auto& hook : manifests_[pluginId].hooks) {
            auto range = hooks_.equal_range(hook.eventType);
            for (auto hookIt = range.first; hookIt != range.second;) {
                if (hookIt->second.name == hook.name) {
                    hookIt = hooks_.erase(hookIt);
                } else {
                    ++hookIt;
                }
            }
        }
    }

    it->second.state = PluginState::Unloaded;
    it->second.loaded = false;
    it->second.enabled = false;
    logger_.info("Unloaded plugin for reload: {}", pluginId);

    // Load inline (same logic as loadPlugin but without acquiring mutex)
    std::string loadPluginId;
    auto lastSlash = path.rfind('/');
    auto lastDot = path.rfind('.');
    if (lastSlash != std::string::npos) {
        loadPluginId = path.substr(lastSlash + 1);
    } else {
        loadPluginId = path;
    }
    if (lastDot != std::string::npos && lastDot > (lastSlash != std::string::npos ? lastSlash : 0)) {
        loadPluginId = loadPluginId.substr(0, loadPluginId.rfind('.'));
    }

    auto manifestIt = manifests_.find(loadPluginId);
    if (manifestIt != manifests_.end()) {
        loadPluginId = manifestIt->second.id;
    }

    // Create plugin info
    PluginInfo info;
    info.id = loadPluginId;
    info.loaded = true;
    info.enabled = false;
    info.state = PluginState::Loaded;

    if (manifestIt != manifests_.end()) {
        info.name = manifestIt->second.name;
        info.version = manifestIt->second.version;
        info.author = manifestIt->second.author;
        info.description = manifestIt->second.description;

        for (const auto& hook : manifestIt->second.hooks) {
            hooks_.emplace(hook.eventType, hook);
        }
    } else {
        info.name = loadPluginId;
        info.version = "1.0.0";
    }

    plugins_[loadPluginId] = info;
    logger_.info("Reloaded plugin: {}", pluginId);
    return true;
}

std::vector<PluginInfo> PluginManager::getPlugins() {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<PluginInfo> result;
    result.reserve(plugins_.size());
    for (const auto& [id, info] : plugins_) {
        result.push_back(info);
    }
    return result;
}

bool PluginManager::enablePlugin(const std::string& pluginId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = plugins_.find(pluginId);
    if (it == plugins_.end()) {
        logger_.error("Cannot enable plugin: {} not found", pluginId);
        return false;
    }

    if (it->second.state != PluginState::Loaded && it->second.state != PluginState::Disabled) {
        logger_.error("Cannot enable plugin {}: invalid state", pluginId);
        return false;
    }

    it->second.state = PluginState::Enabled;
    it->second.enabled = true;
    logger_.info("Enabled plugin: {}", pluginId);
    return true;
}

bool PluginManager::disablePlugin(const std::string& pluginId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = plugins_.find(pluginId);
    if (it == plugins_.end()) {
        logger_.error("Cannot disable plugin: {} not found", pluginId);
        return false;
    }

    if (it->second.state != PluginState::Enabled && it->second.state != PluginState::Loaded) {
        logger_.error("Cannot disable plugin {}: invalid state", pluginId);
        return false;
    }

    it->second.state = PluginState::Disabled;
    it->second.enabled = false;
    logger_.info("Disabled plugin: {}", pluginId);
    return true;
}

std::optional<PluginState> PluginManager::getPluginState(const std::string& pluginId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = plugins_.find(pluginId);
    if (it == plugins_.end()) {
        return std::nullopt;
    }
    return it->second.state;
}

bool PluginManager::setPluginPermissions(const std::string& pluginId,
                                          const std::vector<PluginPermission>& permissions) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = plugins_.find(pluginId);
    if (it == plugins_.end()) {
        logger_.error("Cannot set permissions: plugin {} not found", pluginId);
        return false;
    }

    permissions_[pluginId] = std::set<PluginPermission>(permissions.begin(), permissions.end());
    logger_.info("Set {} permissions for plugin {}", permissions.size(), pluginId);
    return true;
}

std::vector<PluginPermission> PluginManager::getPluginPermissions(const std::string& pluginId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = permissions_.find(pluginId);
    if (it == permissions_.end()) {
        return {};
    }
    return std::vector<PluginPermission>(it->second.begin(), it->second.end());
}

bool PluginManager::checkPermission(const std::string& pluginId, PluginPermission permission) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = permissions_.find(pluginId);
    if (it == permissions_.end()) {
        return false;
    }
    return it->second.count(permission) > 0;
}

std::vector<std::string> PluginManager::resolveDependencies(const std::string& pluginId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto manifestIt = manifests_.find(pluginId);
    if (manifestIt == manifests_.end()) {
        // No manifest means no dependencies
        return {};
    }

    // Topological sort of dependency graph using BFS (Kahn's algorithm)
    std::unordered_map<std::string, std::vector<std::string>> graph;
    std::unordered_map<std::string, int> inDegree;
    std::unordered_set<std::string> allNodes;

    // Build graph starting from pluginId
    std::queue<std::string> toProcess;
    toProcess.push(pluginId);
    allNodes.insert(pluginId);

    while (!toProcess.empty()) {
        std::string current = toProcess.front();
        toProcess.pop();

        auto mIt = manifests_.find(current);
        if (mIt == manifests_.end()) continue;

        for (const auto& dep : mIt->second.dependencies) {
            // Track whether this is a new node before inserting
            bool isNew = (allNodes.find(dep.pluginId) == allNodes.end());
            allNodes.insert(dep.pluginId);
            graph[dep.pluginId].push_back(current);

            if (inDegree.find(current) == inDegree.end()) {
                inDegree[current] = 0;
            }
            inDegree[current]++;

            if (inDegree.find(dep.pluginId) == inDegree.end()) {
                inDegree[dep.pluginId] = 0;
            }

            // Process transitive dependencies if this is a newly discovered node
            if (isNew) {
                toProcess.push(dep.pluginId);
            }
        }
    }

    // Ensure all nodes have in-degree entry
    for (const auto& node : allNodes) {
        if (inDegree.find(node) == inDegree.end()) {
            inDegree[node] = 0;
        }
    }

    // Kahn's algorithm
    std::queue<std::string> ready;
    for (const auto& [node, degree] : inDegree) {
        if (degree == 0) {
            ready.push(node);
        }
    }

    std::vector<std::string> order;
    while (!ready.empty()) {
        std::string node = ready.front();
        ready.pop();
        order.push_back(node);

        if (graph.count(node)) {
            for (const auto& neighbor : graph[node]) {
                inDegree[neighbor]--;
                if (inDegree[neighbor] == 0) {
                    ready.push(neighbor);
                }
            }
        }
    }

    // If order doesn't contain all nodes, there is a cycle
    if (order.size() != allNodes.size()) {
        logger_.error("Circular dependency detected for plugin: {}", pluginId);
        return {"CIRCULAR_DEPENDENCY_DETECTED"};
    }

    // Return order without the plugin itself
    std::vector<std::string> result;
    for (const auto& node : order) {
        if (node != pluginId) {
            result.push_back(node);
        }
    }

    // Check for missing dependencies
    for (const auto& dep : manifestIt->second.dependencies) {
        if (dep.required && manifests_.find(dep.pluginId) == manifests_.end()
            && plugins_.find(dep.pluginId) == plugins_.end()) {
            // Return missing dep marker
            result.clear();
            result.push_back("MISSING:" + dep.pluginId);
            return result;
        }
    }

    return result;
}

std::vector<PluginHook> PluginManager::getPluginHooks(const std::string& eventType) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<PluginHook> result;
    auto range = hooks_.equal_range(eventType);
    for (auto it = range.first; it != range.second; ++it) {
        result.push_back(it->second);
    }

    // Sort by priority (higher priority first)
    std::sort(result.begin(), result.end(),
              [](const PluginHook& a, const PluginHook& b) {
                  return a.priority > b.priority;
              });

    return result;
}

std::vector<MarketplaceEntry> PluginManager::getMarketplace() {
    std::lock_guard<std::mutex> lock(mutex_);
    return marketplace_;
}

std::vector<MarketplaceEntry> PluginManager::searchMarketplace(const std::string& query) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (query.empty()) {
        return marketplace_;
    }

    std::string lowerQuery = query;
    std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(),
        [](char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); });

    std::vector<MarketplaceEntry> results;
    for (const auto& entry : marketplace_) {
        std::string lowerName = entry.name;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(),
            [](char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); });
        std::string lowerDesc = entry.description;
        std::transform(lowerDesc.begin(), lowerDesc.end(), lowerDesc.begin(),
            [](char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); });

        if (lowerName.find(lowerQuery) != std::string::npos ||
            lowerDesc.find(lowerQuery) != std::string::npos) {
            results.push_back(entry);
        }
    }
    return results;
}

std::optional<MarketplaceEntry> PluginManager::getMarketplaceEntry(const std::string& pluginId) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& entry : marketplace_) {
        if (entry.id == pluginId) {
            return entry;
        }
    }
    return std::nullopt;
}

bool PluginManager::checkCompatibility(const std::string& pluginId, const std::string& version) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& entry : marketplace_) {
        if (entry.id == pluginId) {
            // Check if the version is in compatible versions list
            if (entry.compatibleVersions.empty()) {
                return true;  // No restrictions means compatible
            }
            for (const auto& v : entry.compatibleVersions) {
                if (v == version) {
                    return true;
                }
            }
            return false;
        }
    }
    return false;
}

bool PluginManager::installFromMarketplace(const std::string& pluginId) {
    // Check marketplace entry exists (without holding lock for loadPlugin)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        bool found = false;
        for (const auto& entry : marketplace_) {
            if (entry.id == pluginId) {
                found = true;
                break;
            }
        }

        if (!found) {
            logger_.error("Plugin {} not found in marketplace", pluginId);
            return false;
        }
    }

    // Load the plugin using its ID as path
    if (!loadPlugin(pluginId)) {
        logger_.error("Failed to install plugin {} from marketplace", pluginId);
        return false;
    }

    logger_.info("Installed plugin {} from marketplace", pluginId);
    return true;
}

void PluginManager::addMarketplaceEntry(const MarketplaceEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    marketplace_.push_back(entry);
    logger_.info("Added marketplace entry: {}", entry.id);
}

void PluginManager::registerManifest(const PluginManifest& manifest) {
    std::lock_guard<std::mutex> lock(mutex_);
    manifests_[manifest.id] = manifest;
    logger_.info("Registered manifest for plugin: {}", manifest.id);
}

} // namespace ThreatOne::Plugin
