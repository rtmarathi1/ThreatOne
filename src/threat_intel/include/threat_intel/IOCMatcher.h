#pragma once

// ThreatOne Threat Intel - IOC Matching Engine
// Efficiently matches observed indicators against the IOC database

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <shared_mutex>

#include <core/Error.h>
#include <core/Logger.h>
#include "IOCTypes.h"
#include "IOCManager.h"

namespace ThreatOne::ThreatIntel {

// Result of matching an indicator against the IOC database
struct MatchResult {
    IOC matchedIOC;
    std::string matchType;    // "exact", "domain_suffix", "ip_prefix", "url_contains"
    double confidence = 0.0;  // 0.0 - 1.0
};

// Trie node for IP prefix matching
struct TrieNode {
    std::unordered_map<char, std::unique_ptr<TrieNode>> children;
    std::vector<uint64_t> iocIds;  // IOC IDs that terminate here
    bool isEndOfPrefix = false;
};

// Efficiently matches indicators against the IOC database
class IOCMatcher {
public:
    IOCMatcher();

    // Load IOCs from an IOCManager into matching data structures
    void loadIOCs(const IOCManager& manager);

    // Add a single IOC to the matcher
    void addIOC(const IOC& ioc);

    // Clear all loaded data
    void clear();

    // Exact match for hashes, emails (using hash map)
    [[nodiscard]] std::vector<MatchResult> matchExact(const std::string& value) const;

    // Domain suffix matching (e.g., "evil.com" matches "sub.evil.com")
    [[nodiscard]] std::vector<MatchResult> matchDomain(const std::string& domain) const;

    // IP prefix matching using trie (supports CIDR-like matching)
    [[nodiscard]] std::vector<MatchResult> matchIP(const std::string& ip) const;

    // URL matching (checks domain and full URL)
    [[nodiscard]] std::vector<MatchResult> matchURL(const std::string& url) const;

    // Match all - tries all match types and returns combined results
    [[nodiscard]] std::vector<MatchResult> matchAll(const std::string& indicator) const;

    // Get statistics
    [[nodiscard]] size_t exactEntryCount() const;
    [[nodiscard]] size_t domainEntryCount() const;
    [[nodiscard]] size_t ipEntryCount() const;

private:
    // Lock-free implementations called from within already-locked contexts
    std::vector<MatchResult> matchExact_impl(const std::string& value) const;
    std::vector<MatchResult> matchDomain_impl(const std::string& domain) const;
    std::vector<MatchResult> matchIP_impl(const std::string& ip) const;
    std::vector<MatchResult> matchURL_impl(const std::string& url) const;

    void insertIntoTrie(const std::string& prefix, uint64_t iocId);
    std::vector<uint64_t> searchTrie(const std::string& ip) const;

    mutable std::shared_mutex mutex_;

    // Hash-based exact matching (for hashes, emails, file paths)
    std::unordered_map<std::string, std::vector<uint64_t>> exactMap_;

    // Domain suffix matching storage
    std::unordered_map<std::string, std::vector<uint64_t>> domainMap_;

    // IP prefix trie
    std::unique_ptr<TrieNode> ipTrie_;

    // URL matching (domain extraction + exact)
    std::unordered_map<std::string, std::vector<uint64_t>> urlMap_;

    // All IOCs for lookup by ID
    std::unordered_map<uint64_t, IOC> iocStore_;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::ThreatIntel
