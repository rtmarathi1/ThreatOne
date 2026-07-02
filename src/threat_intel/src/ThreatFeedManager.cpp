#include "threat_intel/ThreatFeedManager.h"
#include "threat_intel/StixParser.h"
#include "threat_intel/CsvParser.h"
#include "threat_intel/PlainTextParser.h"
#include "threat_intel/OpenIOCParser.h"
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <utility>
#include <vector>

namespace ThreatOne::ThreatIntel {

ThreatFeedManager::ThreatFeedManager(std::shared_ptr<IOCManager> iocManager)
    : iocManager_(std::move(iocManager))
    , logger_(Core::Logger::instance().getModuleLogger("ThreatIntel.FeedManager")) {
}

Core::Result<uint64_t> ThreatFeedManager::addFeed(FeedConfig config) {
    std::unique_lock lock(mutex_);

    if (config.name.empty()) {
        return Core::Result<uint64_t>::err(
            Core::Error("Feed name cannot be empty",
                        Core::ErrorCategory::Validation));
    }

    config.id = nextFeedId_++;
    uint64_t id = config.id;
    feeds_.emplace(id, std::move(config));
    logger_.info("Added feed id={}", id);
    return Core::Result<uint64_t>::ok(id);
}

Core::Result<void> ThreatFeedManager::removeFeed(uint64_t feedId) {
    std::unique_lock lock(mutex_);

    auto it = feeds_.find(feedId);
    if (it == feeds_.end()) {
        return Core::Result<void>::err(
            Core::Error("Feed not found",
                        Core::ErrorCategory::Validation));
    }

    feeds_.erase(it);
    logger_.info("Removed feed id={}", feedId);
    return Core::Result<void>::ok();
}

Core::Result<FeedConfig> ThreatFeedManager::getFeed(uint64_t feedId) const {
    std::shared_lock lock(mutex_);

    auto it = feeds_.find(feedId);
    if (it == feeds_.end()) {
        return Core::Result<FeedConfig>::err(
            Core::Error("Feed not found",
                        Core::ErrorCategory::Validation));
    }

    return Core::Result<FeedConfig>::ok(it->second);
}

std::vector<FeedConfig> ThreatFeedManager::listFeeds() const {
    std::shared_lock lock(mutex_);

    std::vector<FeedConfig> result;
    result.reserve(feeds_.size());
    for (const auto& [id, feed] : feeds_) {
        result.push_back(feed);
    }
    return result;
}

Core::Result<size_t> ThreatFeedManager::processFeedData(
    uint64_t feedId, const std::string& rawData) {
    FeedFormat format;
    {
        std::shared_lock lock(mutex_);
        auto it = feeds_.find(feedId);
        if (it == feeds_.end()) {
            return Core::Result<size_t>::err(
                Core::Error("Feed not found",
                            Core::ErrorCategory::Validation));
        }
        format = it->second.format;
    }

    auto parser = getParser(format);
    if (!parser) {
        return Core::Result<size_t>::err(
            Core::Error("No parser available for feed format",
                        Core::ErrorCategory::Internal));
    }

    auto parseResult = parser->parse(rawData);
    if (!parseResult) {
        return Core::Result<size_t>::err(parseResult.error());
    }

    auto& iocs = parseResult.value();
    size_t addedCount = 0;

    for (auto& ioc : iocs) {
        auto addResult = iocManager_->addIOC(std::move(ioc));
        if (addResult) {
            ++addedCount;
        }
    }

    // Update last refresh time
    {
        std::unique_lock lock(mutex_);
        auto it = feeds_.find(feedId);
        if (it != feeds_.end()) {
            it->second.lastRefresh = std::chrono::system_clock::now();
        }
    }

    logger_.info("Processed feed id={}, added {} IOCs", feedId, addedCount);
    return Core::Result<size_t>::ok(addedCount);
}

std::vector<FeedConfig> ThreatFeedManager::checkFeedRefresh() const {
    std::shared_lock lock(mutex_);

    auto now = std::chrono::system_clock::now();
    std::vector<FeedConfig> needsRefresh;

    for (const auto& [id, feed] : feeds_) {
        if (!feed.enabled) continue;

        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - feed.lastRefresh);
        if (elapsed >= feed.refreshInterval) {
            needsRefresh.push_back(feed);
        }
    }

    return needsRefresh;
}

size_t ThreatFeedManager::feedCount() const {
    std::shared_lock lock(mutex_);
    return feeds_.size();
}

std::shared_ptr<IFeedParser> ThreatFeedManager::getParser(FeedFormat format) const {
    switch (format) {
        case FeedFormat::STIX_JSON:
            return std::make_shared<StixParser>();
        case FeedFormat::CSV:
            return std::make_shared<CsvParser>();
        case FeedFormat::PlainText:
            return std::make_shared<PlainTextParser>();
        case FeedFormat::OpenIOC_XML:
            return std::make_shared<OpenIOCParser>();
    }
    return nullptr;
}

} // namespace ThreatOne::ThreatIntel
