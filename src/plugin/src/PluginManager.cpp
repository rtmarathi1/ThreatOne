#include "plugin/PluginManager.h"

namespace ThreatOne::Plugin {

PluginManager::PluginManager()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("PluginManager")) {
    logger_.info("PluginManager initialized (stub)");
}

bool PluginManager::loadPlugin(const std::string& path) {
    logger_.info("loadPlugin called: {}", path);
    return true;
}

bool PluginManager::unloadPlugin(const std::string& pluginId) {
    logger_.info("unloadPlugin called: {}", pluginId);
    return true;
}

std::vector<PluginInfo> PluginManager::getPlugins() {
    logger_.info("getPlugins called");
    return {};
}

bool PluginManager::enablePlugin(const std::string& pluginId) {
    logger_.info("enablePlugin called: {}", pluginId);
    return true;
}

bool PluginManager::disablePlugin(const std::string& pluginId) {
    logger_.info("disablePlugin called: {}", pluginId);
    return true;
}

std::vector<MarketplaceEntry> PluginManager::getMarketplace() {
    logger_.info("getMarketplace called");
    return {};
}

bool PluginManager::installFromMarketplace(const std::string& pluginId) {
    logger_.info("installFromMarketplace called: {}", pluginId);
    return true;
}

} // namespace ThreatOne::Plugin
