#include "identity/AuditLogger.h"
#include "identity/AuthenticationManager.h"

#include <algorithm>
#include <sstream>

namespace ThreatOne::Identity {

AuditLogger::AuditLogger() = default;

std::string AuditLogger::generateId() {
    return "AUDIT-" + std::to_string(nextId_++);
}

std::string AuditLogger::computeEntryHash(const AuditEntry& entry) {
    std::ostringstream oss;
    oss << entry.id;
    oss << entry.userId;
    oss << entry.action;
    oss << entry.resource;
    oss << static_cast<int>(entry.outcome);
    oss << entry.sourceIP;
    oss << entry.details;
    oss << entry.previousHash;
    auto tp = entry.timestamp.time_since_epoch().count();
    oss << tp;
    return AuthenticationManager::sha256(oss.str());
}

std::string AuditLogger::logEvent(const std::string& userId, const std::string& action,
                                    const std::string& resource, AuditOutcome outcome,
                                    const std::string& sourceIP,
                                    const std::string& details) {
    AuditEntry entry;
    entry.id = generateId();
    entry.timestamp = std::chrono::system_clock::now();
    entry.userId = userId;
    entry.action = action;
    entry.resource = resource;
    entry.outcome = outcome;
    entry.sourceIP = sourceIP;
    entry.details = details;

    // Chain to previous entry
    if (!entries_.empty()) {
        entry.previousHash = entries_.back().hash;
    }

    // Compute hash for this entry
    entry.hash = computeEntryHash(entry);

    entries_.push_back(entry);

    // Enforce retention if needed
    if (retentionPolicy_.enabled && entries_.size() > retentionPolicy_.maxEntries) {
        enforceRetention();
    }

    return entry.id;
}

std::vector<AuditEntry> AuditLogger::search(const AuditSearchCriteria& criteria) const {
    std::vector<AuditEntry> results;

    for (const auto& entry : entries_) {
        if (!criteria.userId.empty() && entry.userId != criteria.userId) {
            continue;
        }
        if (!criteria.action.empty() && entry.action != criteria.action) {
            continue;
        }
        if (!criteria.resource.empty() && entry.resource != criteria.resource) {
            continue;
        }
        if (criteria.filterByOutcome && entry.outcome != criteria.outcome) {
            continue;
        }
        if (criteria.startTime != std::chrono::system_clock::time_point{} &&
            entry.timestamp < criteria.startTime) {
            continue;
        }
        if (criteria.endTime != std::chrono::system_clock::time_point{} &&
            entry.timestamp > criteria.endTime) {
            continue;
        }

        results.push_back(entry);
        if (results.size() >= criteria.maxResults) {
            break;
        }
    }

    return results;
}

std::vector<AuditEntry> AuditLogger::getEntries(std::size_t count, std::size_t offset) const {
    if (offset >= entries_.size()) {
        return {};
    }
    auto begin = entries_.begin() + static_cast<std::ptrdiff_t>(offset);
    auto end = begin + static_cast<std::ptrdiff_t>(std::min(count, entries_.size() - offset));
    return {begin, end};
}

AuditEntry AuditLogger::getEntry(const std::string& id) const {
    for (const auto& entry : entries_) {
        if (entry.id == id) {
            return entry;
        }
    }
    return {};
}

void AuditLogger::setRetentionPolicy(const RetentionPolicy& policy) {
    retentionPolicy_ = policy;
}

RetentionPolicy AuditLogger::getRetentionPolicy() const {
    return retentionPolicy_;
}

std::size_t AuditLogger::enforceRetention() {
    if (!retentionPolicy_.enabled) {
        return 0;
    }

    std::size_t removed = 0;
    auto now = std::chrono::system_clock::now();

    // Remove entries older than maxAge
    auto it = entries_.begin();
    while (it != entries_.end()) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - it->timestamp);
        if (age > retentionPolicy_.maxAge) {
            it = entries_.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }

    // Remove oldest entries if over maxEntries
    while (entries_.size() > retentionPolicy_.maxEntries) {
        entries_.erase(entries_.begin());
        ++removed;
    }

    return removed;
}

bool AuditLogger::verifyChainIntegrity() const {
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        // Verify the hash of each entry
        std::string expectedHash = computeEntryHash(entries_[i]);
        if (entries_[i].hash != expectedHash) {
            return false;
        }

        // Verify chain linkage
        if (i > 0) {
            if (entries_[i].previousHash != entries_[i - 1].hash) {
                return false;
            }
        } else {
            // First entry should have empty previousHash
            if (!entries_[i].previousHash.empty()) {
                return false;
            }
        }
    }
    return true;
}

bool AuditLogger::verifyEntry(const std::string& id) const {
    for (const auto& entry : entries_) {
        if (entry.id == id) {
            std::string expectedHash = computeEntryHash(entry);
            return entry.hash == expectedHash;
        }
    }
    return false;
}

std::size_t AuditLogger::getEntryCount() const {
    return entries_.size();
}

} // namespace ThreatOne::Identity
