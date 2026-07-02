#pragma once

#include "plugin/IPluginManager.h"
#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>
#include <queue>
#include <unordered_set>
#include <unordered_map>

namespace ThreatOne::Plugin {

struct ResolvedDependency {
    std::string pluginId;
    std::string requiredVersion;
    bool satisfied = false;
    bool optional = false;
};

class DependencyResolver {
public:
    DependencyResolver();
    ~DependencyResolver() = default;

    // Manifest registration
    void registerManifest(const PluginManifest& manifest);
    void unregisterManifest(const std::string& pluginId);
    [[nodiscard]] bool hasManifest(const std::string& pluginId) const;
    [[nodiscard]] PluginManifest getManifest(const std::string& pluginId) const;

    // Dependency resolution
    [[nodiscard]] std::vector<std::string> resolve(const std::string& pluginId) const;
    [[nodiscard]] std::vector<ResolvedDependency> getDirectDependencies(const std::string& pluginId) const;
    [[nodiscard]] std::vector<std::string> getReverseDependencies(const std::string& pluginId) const;

    // Validation
    [[nodiscard]] bool hasCircularDependency(const std::string& pluginId) const;
    [[nodiscard]] bool areDependenciesSatisfied(const std::string& pluginId, const std::vector<std::string>& loadedPlugins) const;

    // Version constraint checking
    [[nodiscard]] bool versionSatisfiesConstraint(const std::string& version, const std::string& constraint) const;

    [[nodiscard]] size_t getManifestCount() const;

private:
    mutable std::mutex mutex_;
    std::map<std::string, PluginManifest> manifests_;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Plugin
