#pragma once

#include <string>
#include <vector>

namespace ThreatOne::Plugin {

struct PluginInfo {
    std::string id;
    std::string name;
    std::string version;
    std::string author;
    std::string description;
    bool enabled = false;
    bool loaded = false;
};

struct MarketplaceEntry {
    std::string id;
    std::string name;
    std::string version;
    std::string author;
    std::string description;
    uint64_t downloads = 0;
    double rating = 0.0;
};

class IPluginManager {
public:
    virtual ~IPluginManager() = default;

    virtual bool loadPlugin(const std::string& path) = 0;
    virtual bool unloadPlugin(const std::string& pluginId) = 0;
    virtual std::vector<PluginInfo> getPlugins() = 0;
    virtual bool enablePlugin(const std::string& pluginId) = 0;
    virtual bool disablePlugin(const std::string& pluginId) = 0;
    virtual std::vector<MarketplaceEntry> getMarketplace() = 0;
    virtual bool installFromMarketplace(const std::string& pluginId) = 0;
};

} // namespace ThreatOne::Plugin
