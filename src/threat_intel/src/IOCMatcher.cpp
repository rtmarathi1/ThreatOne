#include "threat_intel/IOCMatcher.h"

#include <algorithm>

namespace ThreatOne::ThreatIntel {

IOCMatcher::IOCMatcher()
    : ipTrie_(std::make_unique<TrieNode>())
    , logger_(Core::Logger::instance().getModuleLogger("ThreatIntel.IOCMatcher")) {
}

void IOCMatcher::loadIOCs(const IOCManager& manager) {
    auto allIOCs = manager.getActiveIOCs();
    for (const auto& ioc : allIOCs) {
        addIOC(ioc);
    }
    logger_.info("Loaded {} active IOCs into matcher", allIOCs.size());
}

void IOCMatcher::addIOC(const IOC& ioc) {
    std::unique_lock lock(mutex_);

    iocStore_[ioc.id] = ioc;

    switch (ioc.type) {
        case IOCType::Hash_MD5:
        case IOCType::Hash_SHA1:
        case IOCType::Hash_SHA256:
        case IOCType::EmailAddress:
        case IOCType::FilePath:
            exactMap_[ioc.value].push_back(ioc.id);
            break;
        case IOCType::Domain: {
            // Store pre-lowercased domain to avoid per-query transform
            std::string lowerDomain = ioc.value;
            std::transform(lowerDomain.begin(), lowerDomain.end(), lowerDomain.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            domainMap_[lowerDomain].push_back(ioc.id);
            break;
        }
        case IOCType::IP:
            insertIntoTrie(ioc.value, ioc.id);
            break;
        case IOCType::URL:
            urlMap_[ioc.value].push_back(ioc.id);
            // Also extract domain from URL for domain matching
            {
                auto pos = ioc.value.find("://");
                if (pos != std::string::npos) {
                    auto domStart = pos + 3;
                    auto domEnd = ioc.value.find('/', domStart);
                    if (domEnd == std::string::npos) {
                        domEnd = ioc.value.size();
                    }
                    auto domain = ioc.value.substr(domStart, domEnd - domStart);
                    // Remove port if present
                    auto portPos = domain.find(':');
                    if (portPos != std::string::npos) {
                        domain = domain.substr(0, portPos);
                    }
                    // Store pre-lowercased
                    std::transform(domain.begin(), domain.end(), domain.begin(),
                                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                    domainMap_[domain].push_back(ioc.id);
                }
            }
            break;
    }
}

void IOCMatcher::clear() {
    std::unique_lock lock(mutex_);
    exactMap_.clear();
    domainMap_.clear();
    ipTrie_ = std::make_unique<TrieNode>();
    urlMap_.clear();
    iocStore_.clear();
}

// --- Public locking wrappers ---

std::vector<MatchResult> IOCMatcher::matchExact(const std::string& value) const {
    std::shared_lock lock(mutex_);
    return matchExact_impl(value);
}

std::vector<MatchResult> IOCMatcher::matchDomain(const std::string& domain) const {
    std::shared_lock lock(mutex_);
    return matchDomain_impl(domain);
}

std::vector<MatchResult> IOCMatcher::matchIP(const std::string& ip) const {
    std::shared_lock lock(mutex_);
    return matchIP_impl(ip);
}

std::vector<MatchResult> IOCMatcher::matchURL(const std::string& url) const {
    std::shared_lock lock(mutex_);
    return matchURL_impl(url);
}

std::vector<MatchResult> IOCMatcher::matchAll(const std::string& indicator) const {
    std::shared_lock lock(mutex_);

    std::vector<MatchResult> results;

    // Try exact match first
    auto exact = matchExact_impl(indicator);
    results.insert(results.end(), exact.begin(), exact.end());

    // Try domain match
    auto domain = matchDomain_impl(indicator);
    results.insert(results.end(), domain.begin(), domain.end());

    // Try IP match
    auto ip = matchIP_impl(indicator);
    results.insert(results.end(), ip.begin(), ip.end());

    // Try URL match
    auto url = matchURL_impl(indicator);
    results.insert(results.end(), url.begin(), url.end());

    // Deduplicate by IOC ID
    std::vector<MatchResult> deduplicated;
    std::unordered_map<uint64_t, bool> seen;
    for (auto& mr : results) {
        if (!seen[mr.matchedIOC.id]) {
            seen[mr.matchedIOC.id] = true;
            deduplicated.push_back(std::move(mr));
        }
    }

    return deduplicated;
}

// --- Private lock-free implementations ---

std::vector<MatchResult> IOCMatcher::matchExact_impl(const std::string& value) const {
    std::vector<MatchResult> results;
    auto it = exactMap_.find(value);
    if (it != exactMap_.end()) {
        for (uint64_t id : it->second) {
            auto iocIt = iocStore_.find(id);
            if (iocIt != iocStore_.end()) {
                MatchResult mr;
                mr.matchedIOC = iocIt->second;
                mr.matchType = "exact";
                mr.confidence = iocIt->second.confidence;
                results.push_back(mr);
            }
        }
    }
    return results;
}

std::vector<MatchResult> IOCMatcher::matchDomain_impl(const std::string& domain) const {
    std::vector<MatchResult> results;

    // Convert query to lowercase (domains in the map are already pre-lowercased)
    std::string lowerDomain = domain;
    std::transform(lowerDomain.begin(), lowerDomain.end(), lowerDomain.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    for (const auto& [storedDomain, ids] : domainMap_) {
        bool match = false;
        double confidence = 1.0;

        if (lowerDomain == storedDomain) {
            match = true;
            confidence = 1.0;
        } else if (lowerDomain.size() > storedDomain.size()) {
            // Check if domain ends with ".storedDomain"
            auto suffix = "." + storedDomain;
            if (lowerDomain.size() >= suffix.size() &&
                lowerDomain.compare(lowerDomain.size() - suffix.size(),
                                    suffix.size(), suffix) == 0) {
                match = true;
                confidence = 0.9; // Subdomain match is slightly less confident
            }
        }

        if (match) {
            for (uint64_t id : ids) {
                auto iocIt = iocStore_.find(id);
                if (iocIt != iocStore_.end()) {
                    MatchResult mr;
                    mr.matchedIOC = iocIt->second;
                    mr.matchType = "domain_suffix";
                    mr.confidence = iocIt->second.confidence * confidence;
                    results.push_back(mr);
                }
            }
        }
    }
    return results;
}

std::vector<MatchResult> IOCMatcher::matchIP_impl(const std::string& ip) const {
    std::vector<MatchResult> results;
    auto matchedIds = searchTrie(ip);

    for (uint64_t id : matchedIds) {
        auto iocIt = iocStore_.find(id);
        if (iocIt != iocStore_.end()) {
            MatchResult mr;
            mr.matchedIOC = iocIt->second;
            mr.matchType = "ip_prefix";
            mr.confidence = iocIt->second.confidence;
            results.push_back(mr);
        }
    }
    return results;
}

std::vector<MatchResult> IOCMatcher::matchURL_impl(const std::string& url) const {
    std::vector<MatchResult> results;

    // Exact URL match
    auto it = urlMap_.find(url);
    if (it != urlMap_.end()) {
        for (uint64_t id : it->second) {
            auto iocIt = iocStore_.find(id);
            if (iocIt != iocStore_.end()) {
                MatchResult mr;
                mr.matchedIOC = iocIt->second;
                mr.matchType = "exact";
                mr.confidence = iocIt->second.confidence;
                results.push_back(mr);
            }
        }
    }

    // Also check if the URL's domain matches any domain IOCs
    auto pos = url.find("://");
    if (pos != std::string::npos) {
        auto domStart = pos + 3;
        auto domEnd = url.find('/', domStart);
        if (domEnd == std::string::npos) domEnd = url.size();
        auto domain = url.substr(domStart, domEnd - domStart);
        // Remove port
        auto portPos = domain.find(':');
        if (portPos != std::string::npos) {
            domain = domain.substr(0, portPos);
        }

        // Domains in the map are already pre-lowercased
        std::string lowerDomain = domain;
        std::transform(lowerDomain.begin(), lowerDomain.end(), lowerDomain.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        for (const auto& [storedDomain, ids] : domainMap_) {
            if (lowerDomain == storedDomain ||
                (lowerDomain.size() > storedDomain.size() &&
                 lowerDomain.compare(lowerDomain.size() - storedDomain.size() - 1,
                                     storedDomain.size() + 1,
                                     "." + storedDomain) == 0)) {
                for (uint64_t id : ids) {
                    auto iocIt = iocStore_.find(id);
                    if (iocIt != iocStore_.end()) {
                        // Avoid duplicates from URL entries that also added domains
                        bool duplicate = false;
                        for (const auto& existing : results) {
                            if (existing.matchedIOC.id == id) {
                                duplicate = true;
                                break;
                            }
                        }
                        if (!duplicate) {
                            MatchResult mr;
                            mr.matchedIOC = iocIt->second;
                            mr.matchType = "url_contains";
                            mr.confidence = iocIt->second.confidence * 0.8;
                            results.push_back(mr);
                        }
                    }
                }
            }
        }
    }

    return results;
}

// --- Statistics ---

size_t IOCMatcher::exactEntryCount() const {
    std::shared_lock lock(mutex_);
    return exactMap_.size();
}

size_t IOCMatcher::domainEntryCount() const {
    std::shared_lock lock(mutex_);
    return domainMap_.size();
}

size_t IOCMatcher::ipEntryCount() const {
    std::shared_lock lock(mutex_);
    // Count nodes in trie with IOC IDs
    size_t count = 0;
    for (const auto& [id, ioc] : iocStore_) {
        if (ioc.type == IOCType::IP) {
            ++count;
        }
    }
    return count;
}

// --- Trie operations ---

void IOCMatcher::insertIntoTrie(const std::string& prefix, uint64_t iocId) {
    TrieNode* node = ipTrie_.get();
    for (char c : prefix) {
        if (node->children.find(c) == node->children.end()) {
            node->children[c] = std::make_unique<TrieNode>();
        }
        node = node->children[c].get();
    }
    node->isEndOfPrefix = true;
    node->iocIds.push_back(iocId);
}

std::vector<uint64_t> IOCMatcher::searchTrie(const std::string& ip) const {
    std::vector<uint64_t> results;
    const TrieNode* node = ipTrie_.get();

    for (char c : ip) {
        // Collect any IOCs at intermediate nodes (prefix matches)
        if (node->isEndOfPrefix) {
            results.insert(results.end(), node->iocIds.begin(), node->iocIds.end());
        }

        auto it = node->children.find(c);
        if (it == node->children.end()) {
            break;
        }
        node = it->second.get();
    }

    // Check the final node
    if (node && node->isEndOfPrefix) {
        results.insert(results.end(), node->iocIds.begin(), node->iocIds.end());
    }

    return results;
}

} // namespace ThreatOne::ThreatIntel
