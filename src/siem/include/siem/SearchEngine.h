#pragma once
#include <unordered_map>

#include "siem/ISIEMEngine.h"
#include "siem/LogStorage.h"
#include "core/Logger.h"

#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace ThreatOne::SIEM {

// Aggregation result
struct AggregationResult {
    std::string fieldName;
    std::unordered_map<std::string, int> buckets;
};

class SearchEngine {
public:
    explicit SearchEngine(std::shared_ptr<LogStorage> storage);
    ~SearchEngine() = default;

    // Simple text search across message and source
    [[nodiscard]] std::vector<LogEntry> textSearch(const std::string& query) const;

    // Advanced search with query object
    [[nodiscard]] std::vector<LogEntry> search(const SearchQuery& query) const;

    // Aggregate by a field
    [[nodiscard]] AggregationResult aggregate(const std::string& field,
                                              const SearchQuery& filter = {}) const;

    // Count matching entries
    [[nodiscard]] size_t count(const SearchQuery& query) const;

private:
    [[nodiscard]] bool matchesQuery(const LogEntry& entry, const SearchQuery& query) const;
    [[nodiscard]] bool matchesTextField(const LogEntry& entry, const std::string& text) const;
    [[nodiscard]] bool matchesFieldFilter(const LogEntry& entry,
                                          const std::unordered_map<std::string, std::string>& fields) const;
    [[nodiscard]] bool isWithinTimeRange(const std::string& timestamp,
                                         const std::string& start, const std::string& end) const;

    std::shared_ptr<LogStorage> storage_;
    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::SIEM
