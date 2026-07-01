#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex>

#include "core/Logger.h"

namespace ThreatOne::Network {

struct FilterResult {
    enum class Status {
        Allowed,
        Blocked
    };

    Status status = Status::Allowed;
    std::string reason;
};

class DNSFilter {
public:
    DNSFilter();

    void addToBlocklist(const std::string& domain);
    void addToAllowlist(const std::string& domain);
    void removeFromBlocklist(const std::string& domain);
    void removeFromAllowlist(const std::string& domain);

    void addCategoryBlock(const std::string& category);
    void removeCategoryBlock(const std::string& category);
    void addDomainToCategory(const std::string& domain, const std::string& category);

    FilterResult isAllowed(const std::string& domain) const;
    static bool matchesWildcard(const std::string& pattern, const std::string& domain);

    size_t getBlocklistSize() const;
    size_t getAllowlistSize() const;

private:
    mutable std::mutex mutex_;
    std::unordered_set<std::string> blocklist_;
    std::unordered_set<std::string> allowlist_;
    std::vector<std::string> wildcardBlocklist_;
    std::vector<std::string> wildcardAllowlist_;
    std::unordered_set<std::string> blockedCategories_;
    std::unordered_map<std::string, std::unordered_set<std::string>> domainCategories_;
    Core::ModuleLogger logger_;

    bool isBlockedByCategory(const std::string& domain) const;
    bool matchesAnyWildcard(const std::string& domain, const std::vector<std::string>& patterns) const;
};

} // namespace ThreatOne::Network
