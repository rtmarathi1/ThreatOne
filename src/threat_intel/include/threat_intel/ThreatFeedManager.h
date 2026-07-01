#pragma once

// ThreatOne Threat Intel - Threat Feed Manager
// Manages feed subscriptions, selects parsers, and processes feed data

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <shared_mutex>
#include <cstdint>

#include <core/Error.h>
#include <core/Logger.h>
#include "FeedFormat.h"
#include "IFeedParser.h"
#include "IOCManager.h"

namespace ThreatOne::ThreatIntel {

// Manages threat intelligence feed subscriptions and data processing
class ThreatFeedManager {
public:
    explicit ThreatFeedManager(std::shared_ptr<IOCManager> iocManager);

    // Feed subscription management
    [[nodiscard]] Core::Result<uint64_t> addFeed(FeedConfig config);
    [[nodiscard]] Core::Result<void> removeFeed(uint64_t feedId);
    [[nodiscard]] Core::Result<FeedConfig> getFeed(uint64_t feedId) const;
    [[nodiscard]] std::vector<FeedConfig> listFeeds() const;

    // Process raw data from a feed using the appropriate parser
    [[nodiscard]] Core::Result<size_t> processFeedData(uint64_t feedId,
                                                       const std::string& rawData);

    // Check which feeds need to be refreshed based on their interval
    [[nodiscard]] std::vector<FeedConfig> checkFeedRefresh() const;

    // Get total feed count
    [[nodiscard]] size_t feedCount() const;

private:
    // Get or create the appropriate parser for a feed format
    [[nodiscard]] std::shared_ptr<IFeedParser> getParser(FeedFormat format) const;

    mutable std::shared_mutex mutex_;
    std::shared_ptr<IOCManager> iocManager_;
    std::unordered_map<uint64_t, FeedConfig> feeds_;
    uint64_t nextFeedId_ = 1;
    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::ThreatIntel
