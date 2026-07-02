#include "network/DNSFilter.h"

#include <algorithm>
#include <mutex>
#include <string>
#include <vector>

namespace ThreatOne::Network {

DNSFilter::DNSFilter()
    : logger_(Core::Logger::instance().getModuleLogger("DNSFilter")) {
    logger_.info("DNSFilter initialized");
}

void DNSFilter::addToBlocklist(const std::string& domain) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (domain.find('*') != std::string::npos) {
        wildcardBlocklist_.push_back(domain);
    } else {
        blocklist_.insert(domain);
    }
    logger_.debug("Added to blocklist: {}", domain);
}

void DNSFilter::addToAllowlist(const std::string& domain) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (domain.find('*') != std::string::npos) {
        wildcardAllowlist_.push_back(domain);
    } else {
        allowlist_.insert(domain);
    }
    logger_.debug("Added to allowlist: {}", domain);
}

void DNSFilter::removeFromBlocklist(const std::string& domain) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (domain.find('*') != std::string::npos) {
        wildcardBlocklist_.erase(
            std::remove(wildcardBlocklist_.begin(), wildcardBlocklist_.end(), domain),
            wildcardBlocklist_.end());
    } else {
        blocklist_.erase(domain);
    }
}

void DNSFilter::removeFromAllowlist(const std::string& domain) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (domain.find('*') != std::string::npos) {
        wildcardAllowlist_.erase(
            std::remove(wildcardAllowlist_.begin(), wildcardAllowlist_.end(), domain),
            wildcardAllowlist_.end());
    } else {
        allowlist_.erase(domain);
    }
}

void DNSFilter::addCategoryBlock(const std::string& category) {
    std::lock_guard<std::mutex> lock(mutex_);
    blockedCategories_.insert(category);
    logger_.info("Blocked category: {}", category);
}

void DNSFilter::removeCategoryBlock(const std::string& category) {
    std::lock_guard<std::mutex> lock(mutex_);
    blockedCategories_.erase(category);
}

void DNSFilter::addDomainToCategory(const std::string& domain, const std::string& category) {
    std::lock_guard<std::mutex> lock(mutex_);
    domainCategories_[domain].insert(category);
}

FilterResult DNSFilter::isAllowed(const std::string& domain) const {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check allowlist first (allowlist takes priority)
    if (allowlist_.count(domain) > 0) {
        return {FilterResult::Status::Allowed, "Domain in allowlist"};
    }
    if (matchesAnyWildcard(domain, wildcardAllowlist_)) {
        return {FilterResult::Status::Allowed, "Domain matches allowlist wildcard"};
    }

    // Check exact blocklist match
    if (blocklist_.count(domain) > 0) {
        return {FilterResult::Status::Blocked, "Domain in blocklist"};
    }

    // Check wildcard blocklist
    if (matchesAnyWildcard(domain, wildcardBlocklist_)) {
        return {FilterResult::Status::Blocked, "Domain matches blocklist wildcard"};
    }

    // Check category-based blocking
    if (isBlockedByCategory(domain)) {
        return {FilterResult::Status::Blocked, "Domain blocked by category"};
    }

    return {FilterResult::Status::Allowed, ""};
}

bool DNSFilter::matchesWildcard(const std::string& pattern, const std::string& domain) {
    // Handle *.example.com pattern
    if (pattern.size() >= 2 && pattern[0] == '*' && pattern[1] == '.') {
        std::string suffix = pattern.substr(1); // ".example.com"

        // Check if domain ends with the suffix
        if (domain.size() >= suffix.size()) {
            std::string domainEnd = domain.substr(domain.size() - suffix.size());
            if (domainEnd == suffix) {
                return true;
            }
        }

        // Also match exact domain without wildcard prefix
        // e.g., *.example.com should match "example.com"
        std::string baseDomain = pattern.substr(2); // "example.com"
        if (domain == baseDomain) {
            return true;
        }
    }

    // Exact match
    return pattern == domain;
}

size_t DNSFilter::getBlocklistSize() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return blocklist_.size() + wildcardBlocklist_.size();
}

size_t DNSFilter::getAllowlistSize() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return allowlist_.size() + wildcardAllowlist_.size();
}

bool DNSFilter::isBlockedByCategory(const std::string& domain) const {
    auto it = domainCategories_.find(domain);
    if (it == domainCategories_.end()) {
        return false;
    }

    for (const auto& category : it->second) {
        if (blockedCategories_.count(category) > 0) {
            return true;
        }
    }
    return false;
}

bool DNSFilter::matchesAnyWildcard(const std::string& domain, const std::vector<std::string>& patterns) const {
    for (const auto& pattern : patterns) {
        if (matchesWildcard(pattern, domain)) {
            return true;
        }
    }
    return false;
}

} // namespace ThreatOne::Network
