#pragma once

#include "plugin/IPluginManager.h"
#include "core/Logger.h"

namespace ThreatOne::Plugin {

class PluginManager : public IPluginManager {
public:
    PluginManager();
    ~PluginManager() override = default;

    bool loadPlugin(const std::string& path) override;
    bool unloadPlugin(const std::string& pluginId) override;
    std::vector<PluginInfo> getPlugins() override;
    bool enablePlugin(const std::string& pluginId) override;
    bool disablePlugin(const std::string& pluginId) override;
    std::vector<MarketplaceEntry> getMarketplace() override;
    bool installFromMarketplace(const std::string& pluginId) override;

private:
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Plugin
