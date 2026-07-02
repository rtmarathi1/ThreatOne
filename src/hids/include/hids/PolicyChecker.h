#pragma once

#include "hids/IHIDSEngine.h"
#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>
#include <cstdint>

namespace ThreatOne::HIDS {

enum class PolicyCategory {
    FilePermission,
    ServiceConfig,
    UserAccount,
    NetworkConfig,
    AuditConfig,
    SystemHardening
};

struct SecurityPolicy {
    std::string id;
    std::string name;
    PolicyCategory category = PolicyCategory::FilePermission;
    std::string description;
    std::string expectedValue;
    std::string path;
    std::string severity;
    bool enabled = true;
};

struct PolicyCheckResult {
    std::string policyId;
    std::string policyName;
    bool compliant = false;
    std::string actualValue;
    std::string expectedValue;
    std::string detail;
    std::string checkedAt;
};

struct PolicyComplianceSummary {
    uint64_t totalPolicies = 0;
    uint64_t compliant = 0;
    uint64_t nonCompliant = 0;
    uint64_t skipped = 0;
    double compliancePercent = 0.0;
    std::string lastCheckTime;
};

class PolicyChecker {
public:
    PolicyChecker();
    ~PolicyChecker() = default;

    // Policy management
    std::string addPolicy(const SecurityPolicy& policy);
    bool removePolicy(const std::string& policyId);
    bool enablePolicy(const std::string& policyId);
    bool disablePolicy(const std::string& policyId);
    [[nodiscard]] std::vector<SecurityPolicy> getPolicies() const;
    [[nodiscard]] SecurityPolicy getPolicy(const std::string& policyId) const;

    // Checking
    std::vector<PolicyCheckResult> runAllChecks();
    PolicyCheckResult checkPolicy(const std::string& policyId);
    [[nodiscard]] std::vector<PolicyViolation> getViolations() const;
    void addViolation(const PolicyViolation& violation);

    // Compliance summary
    [[nodiscard]] PolicyComplianceSummary getComplianceSummary() const;
    void clearViolations();

    // Stats
    [[nodiscard]] uint64_t getTotalChecksRun() const;

private:
    std::string generatePolicyId();
    std::string generateViolationId();
    std::string getCurrentTimestamp() const;
    PolicyCheckResult evaluatePolicy(const SecurityPolicy& policy) const;

    mutable std::mutex mutex_;

    std::map<std::string, SecurityPolicy> policies_;
    std::vector<PolicyViolation> violations_;
    std::vector<PolicyCheckResult> lastCheckResults_;

    uint64_t totalChecksRun_ = 0;
    std::string lastCheckTime_;

    int nextPolicyId_ = 1;
    int nextViolationId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::HIDS
