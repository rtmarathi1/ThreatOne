#include "siem/SearchEngine.h"

namespace ThreatOne::SIEM {

SearchEngine::SearchEngine(std::shared_ptr<LogStorage> storage)
    : storage_(std::move(storage))
    , logger_(ThreatOne::Core::Logger::instance().getModuleLogger("SearchEngine")) {
    logger_.info("SearchEngine initialized");
}

std::vector<LogEntry> SearchEngine::textSearch(const std::string& query) const {
    auto allEntries = storage_->getAll();

    std::vector<LogEntry> results;
    for (const auto& entry : allEntries) {
        if (entry.message.find(query) != std::string::npos ||
            entry.source.find(query) != std::string::npos) {
            results.push_back(entry);
        }
    }
    return results;
}

std::vector<LogEntry> SearchEngine::search(const SearchQuery& query) const {
    auto allEntries = storage_->getAll();

    std::vector<LogEntry> results;
    int count = 0;

    for (const auto& entry : allEntries) {
        if (count >= query.limit) break;

        if (matchesQuery(entry, query)) {
            results.push_back(entry);
            count++;
        }
    }
    return results;
}

AggregationResult SearchEngine::aggregate(const std::string& field,
                                           const SearchQuery& filter) const {
    auto allEntries = storage_->getAll();

    AggregationResult result;
    result.fieldName = field;

    for (const auto& entry : allEntries) {
        if (!matchesQuery(entry, filter)) continue;

        std::string value;
        if (field == "source") value = entry.source;
        else if (field == "severity") value = entry.severity;
        else {
            auto it = entry.metadata.find(field);
            if (it != entry.metadata.end()) {
                value = it->second;
            } else {
                continue;
            }
        }
        result.buckets[value]++;
    }

    return result;
}

size_t SearchEngine::count(const SearchQuery& query) const {
    auto allEntries = storage_->getAll();

    size_t cnt = 0;
    for (const auto& entry : allEntries) {
        if (matchesQuery(entry, query)) {
            cnt++;
        }
    }
    return cnt;
}

bool SearchEngine::matchesQuery(const LogEntry& entry, const SearchQuery& query) const {
    // Text filter
    if (!query.text.empty()) {
        if (!matchesTextField(entry, query.text)) {
            return false;
        }
    }

    // Field filters
    if (!query.fields.empty()) {
        if (!matchesFieldFilter(entry, query.fields)) {
            return false;
        }
    }

    // Time range filter
    if (!isWithinTimeRange(entry.timestamp, query.timeStart, query.timeEnd)) {
        return false;
    }

    return true;
}

bool SearchEngine::matchesTextField(const LogEntry& entry, const std::string& text) const {
    return entry.message.find(text) != std::string::npos ||
           entry.source.find(text) != std::string::npos;
}

bool SearchEngine::matchesFieldFilter(const LogEntry& entry,
                                       const std::unordered_map<std::string, std::string>& fields) const {
    for (const auto& [field, value] : fields) {
        if (field == "source" && entry.source != value) return false;
        if (field == "severity" && entry.severity != value) return false;
        if (field == "message" && entry.message.find(value) == std::string::npos) return false;

        // Check metadata
        if (field != "source" && field != "severity" && field != "message") {
            auto it = entry.metadata.find(field);
            if (it == entry.metadata.end() || it->second != value) {
                return false;
            }
        }
    }
    return true;
}

bool SearchEngine::isWithinTimeRange(const std::string& timestamp,
                                      const std::string& start, const std::string& end) const {
    if (start.empty() && end.empty()) return true;
    if (!start.empty() && timestamp < start) return false;
    if (!end.empty() && timestamp > end) return false;
    return true;
}

} // namespace ThreatOne::SIEM
