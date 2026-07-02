#include "plugin/DependencyResolver.h"
#include <unordered_map>
#include <mutex>

#include <algorithm>

namespace ThreatOne::Plugin {

DependencyResolver::DependencyResolver()
    : logger_("DependencyResolver") {
    logger_.info("DependencyResolver initialized");
}

void DependencyResolver::registerManifest(const PluginManifest& manifest) {
    std::lock_guard<std::mutex> lock(mutex_);
    manifests_[manifest.id] = manifest;
    logger_.info("Registered manifest for plugin: {}", manifest.id);
}

void DependencyResolver::unregisterManifest(const std::string& pluginId) {
    std::lock_guard<std::mutex> lock(mutex_);
    manifests_.erase(pluginId);
    logger_.info("Unregistered manifest for plugin: {}", pluginId);
}

bool DependencyResolver::hasManifest(const std::string& pluginId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return manifests_.count(pluginId) > 0;
}

PluginManifest DependencyResolver::getManifest(const std::string& pluginId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = manifests_.find(pluginId);
    if (it == manifests_.end()) {
        return {};
    }
    return it->second;
}

std::vector<std::string> DependencyResolver::resolve(const std::string& pluginId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto manifestIt = manifests_.find(pluginId);
    if (manifestIt == manifests_.end()) {
        return {};
    }

    // Topological sort using BFS (Kahn's algorithm)
    std::unordered_map<std::string, std::vector<std::string>> graph;
    std::unordered_map<std::string, int> inDegree;
    std::unordered_set<std::string> allNodes;

    std::queue<std::string> toProcess;
    toProcess.push(pluginId);
    allNodes.insert(pluginId);

    while (!toProcess.empty()) {
        std::string current = toProcess.front();
        toProcess.pop();

        auto mIt = manifests_.find(current);
        if (mIt == manifests_.end()) continue;

        for (const auto& dep : mIt->second.dependencies) {
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

    // Check for circular dependency
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

    // Check for missing required dependencies
    for (const auto& dep : manifestIt->second.dependencies) {
        if (dep.required && manifests_.find(dep.pluginId) == manifests_.end()) {
            result.clear();
            result.push_back("MISSING:" + dep.pluginId);
            return result;
        }
    }

    return result;
}

std::vector<ResolvedDependency> DependencyResolver::getDirectDependencies(const std::string& pluginId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ResolvedDependency> result;
    auto it = manifests_.find(pluginId);
    if (it == manifests_.end()) {
        return result;
    }

    for (const auto& dep : it->second.dependencies) {
        ResolvedDependency rd;
        rd.pluginId = dep.pluginId;
        rd.requiredVersion = dep.minVersion;
        rd.optional = !dep.required;
        rd.satisfied = manifests_.count(dep.pluginId) > 0;
        result.push_back(rd);
    }
    return result;
}

std::vector<std::string> DependencyResolver::getReverseDependencies(const std::string& pluginId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<std::string> result;
    for (const auto& [id, manifest] : manifests_) {
        if (id == pluginId) continue;
        for (const auto& dep : manifest.dependencies) {
            if (dep.pluginId == pluginId) {
                result.push_back(id);
                break;
            }
        }
    }
    return result;
}

bool DependencyResolver::hasCircularDependency(const std::string& pluginId) const {
    auto resolved = resolve(pluginId);
    return !resolved.empty() && resolved[0] == "CIRCULAR_DEPENDENCY_DETECTED";
}

bool DependencyResolver::areDependenciesSatisfied(const std::string& pluginId,
                                                    const std::vector<std::string>& loadedPlugins) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = manifests_.find(pluginId);
    if (it == manifests_.end()) {
        return true;  // No manifest = no deps
    }

    std::unordered_set<std::string> loaded(loadedPlugins.begin(), loadedPlugins.end());

    for (const auto& dep : it->second.dependencies) {
        if (dep.required && loaded.find(dep.pluginId) == loaded.end()) {
            return false;
        }
    }
    return true;
}

bool DependencyResolver::versionSatisfiesConstraint(const std::string& version, const std::string& constraint) const {
    // Simple version comparison: constraint is minimum version
    if (constraint.empty()) return true;
    return version >= constraint;
}

size_t DependencyResolver::getManifestCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return manifests_.size();
}

} // namespace ThreatOne::Plugin
