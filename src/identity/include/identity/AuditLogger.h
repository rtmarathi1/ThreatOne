#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <functional>
#include <cstddef>
#include <cstdint>

namespace ThreatOne::Identity {

enum class AuditOutcome {
    Success,
    Failure,
    Denied,
    Error
};

struct AuditEntry {
    std::string id;
    std::chrono::system_clock::time_point timestamp;
    std::string userId;
    std::string action;
    std::string resource;
    AuditOutcome outcome = AuditOutcome::Success;
    std::string sourceIP;
    std::string details;
    std::string previousHash;
    std::string hash;
};

struct AuditSearchCriteria {
    std::string userId;
    std::string action;
    std::string resource;
    std::chrono::system_clock::time_point startTime;
    std::chrono::system_clock::time_point endTime;
    AuditOutcome outcome = AuditOutcome::Success;
    bool filterByOutcome = false;
    std::size_t maxResults = 100;
};

struct RetentionPolicy {
    std::chrono::seconds maxAge{86400 * 90}; // 90 days default
    std::size_t maxEntries = 100000;
    bool enabled = false; // disabled by default until explicitly configured
};

class IAuditLogger {
public:
    virtual ~IAuditLogger() = default;

    virtual std::string logEvent(const std::string& userId, const std::string& action,
                                  const std::string& resource, AuditOutcome outcome,
                                  const std::string& sourceIP = "",
                                  const std::string& details = "") = 0;

    virtual std::vector<AuditEntry> search(const AuditSearchCriteria& criteria) const = 0;
    virtual std::vector<AuditEntry> getEntries(std::size_t count = 100, std::size_t offset = 0) const = 0;
    virtual AuditEntry getEntry(const std::string& id) const = 0;

    virtual void setRetentionPolicy(const RetentionPolicy& policy) = 0;
    virtual RetentionPolicy getRetentionPolicy() const = 0;
    virtual std::size_t enforceRetention() = 0;

    virtual bool verifyChainIntegrity() const = 0;
    virtual bool verifyEntry(const std::string& id) const = 0;
    virtual std::size_t getEntryCount() const = 0;
};

class AuditLogger : public IAuditLogger {
public:
    AuditLogger();
    ~AuditLogger() override = default;

    std::string logEvent(const std::string& userId, const std::string& action,
                          const std::string& resource, AuditOutcome outcome,
                          const std::string& sourceIP = "",
                          const std::string& details = "") override;

    std::vector<AuditEntry> search(const AuditSearchCriteria& criteria) const override;
    std::vector<AuditEntry> getEntries(std::size_t count = 100, std::size_t offset = 0) const override;
    AuditEntry getEntry(const std::string& id) const override;

    void setRetentionPolicy(const RetentionPolicy& policy) override;
    RetentionPolicy getRetentionPolicy() const override;
    std::size_t enforceRetention() override;

    bool verifyChainIntegrity() const override;
    bool verifyEntry(const std::string& id) const override;
    std::size_t getEntryCount() const override;

    // Utility for computing entry hash
    static std::string computeEntryHash(const AuditEntry& entry);

private:
    std::string generateId();

    std::vector<AuditEntry> entries_;
    RetentionPolicy retentionPolicy_;
    uint64_t nextId_ = 1;
};

} // namespace ThreatOne::Identity
