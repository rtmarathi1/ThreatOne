#include "plugin/PluginMarketplace.h"
#include <optional>
#include <algorithm>
#include <mutex>

namespace ThreatOne::Plugin {

PluginMarketplace::PluginMarketplace()
    : logger_("PluginMarketplace") {
    logger_.info("PluginMarketplace initialized");
}

void PluginMarketplace::addEntry(const MarketplaceEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.push_back(entry);
    logger_.info("Added marketplace entry: {}", entry.id);
}

bool PluginMarketplace::removeEntry(const std::string& pluginId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = std::find_if(entries_.begin(), entries_.end(),
        [&](const MarketplaceEntry& e) { return e.id == pluginId; });

    if (it == entries_.end()) {
        return false;
    }

    entries_.erase(it);
    logger_.info("Removed marketplace entry: {}", pluginId);
    return true;
}

std::vector<MarketplaceEntry> PluginMarketplace::getEntries() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_;
}

std::vector<MarketplaceEntry> PluginMarketplace::search(const std::string& query) const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (query.empty()) {
        return entries_;
    }

    std::string lowerQuery = query;
    std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(),
        [](char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); });

    std::vector<MarketplaceEntry> results;
    for (const auto& entry : entries_) {
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

std::optional<MarketplaceEntry> PluginMarketplace::getEntry(const std::string& pluginId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& entry : entries_) {
        if (entry.id == pluginId) {
            return entry;
        }
    }
    return std::nullopt;
}

bool PluginMarketplace::hasEntry(const std::string& pluginId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& entry : entries_) {
        if (entry.id == pluginId) {
            return true;
        }
    }
    return false;
}

bool PluginMarketplace::checkCompatibility(const std::string& pluginId, const std::string& version) const {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& entry : entries_) {
        if (entry.id == pluginId) {
            if (entry.compatibleVersions.empty()) {
                return true;
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

std::vector<std::string> PluginMarketplace::getCompatibleVersions(const std::string& pluginId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& entry : entries_) {
        if (entry.id == pluginId) {
            return entry.compatibleVersions;
        }
    }
    return {};
}

bool PluginMarketplace::updateRating(const std::string& pluginId, double rating) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& entry : entries_) {
        if (entry.id == pluginId) {
            entry.rating = rating;
            return true;
        }
    }
    return false;
}

bool PluginMarketplace::incrementDownloads(const std::string& pluginId) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& entry : entries_) {
        if (entry.id == pluginId) {
            entry.downloads++;
            return true;
        }
    }
    return false;
}

size_t PluginMarketplace::getEntryCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.size();
}

} // namespace ThreatOne::Plugin
