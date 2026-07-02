#pragma once

#include "plugin/IPluginManager.h"
#include "core/Logger.h"

#include <mutex>
#include <string>
#include <vector>
#include <optional>
#include <algorithm>
#include <cctype>

namespace ThreatOne::Plugin {

class PluginMarketplace {
public:
    PluginMarketplace();
    ~PluginMarketplace() = default;

    // Catalog management
    void addEntry(const MarketplaceEntry& entry);
    bool removeEntry(const std::string& pluginId);
    [[nodiscard]] std::vector<MarketplaceEntry> getEntries() const;

    // Search and discovery
    [[nodiscard]] std::vector<MarketplaceEntry> search(const std::string& query) const;
    [[nodiscard]] std::optional<MarketplaceEntry> getEntry(const std::string& pluginId) const;
    [[nodiscard]] bool hasEntry(const std::string& pluginId) const;

    // Compatibility
    [[nodiscard]] bool checkCompatibility(const std::string& pluginId, const std::string& version) const;
    [[nodiscard]] std::vector<std::string> getCompatibleVersions(const std::string& pluginId) const;

    // Ratings and popularity
    bool updateRating(const std::string& pluginId, double rating);
    bool incrementDownloads(const std::string& pluginId);

    // Metrics
    [[nodiscard]] size_t getEntryCount() const;

private:
    mutable std::mutex mutex_;
    std::vector<MarketplaceEntry> entries_;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Plugin
