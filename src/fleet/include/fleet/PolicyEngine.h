#pragma once

// ThreatOne Fleet - Policy Engine
// Security policy definition, distribution, compliance checking, inheritance

#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <optional>
#include <mutex>

#include "core/Logger.h"

namespace ThreatOne::Fleet {

enum class PolicyRuleType {
    AntivirusEnabled,
    FirewallEnabled,
    MaxScanInterval,
    RequiredAgentVersion,
    BlockedProcesses,
    EncryptionRequired,
    PasswordPolicy,
    Custom
};

enum class PolicyAction {
    Enforce,
    Warn,
    Log,
    Block
};

enum class PolicySeverity {
    Low,
    Medium,
    High,
    Critical
};

struct PolicyRule {
    std::string id;
    PolicyRuleType type = PolicyRuleType::Custom;
    std::string parameters;
    PolicyAction action = PolicyAction::Warn;
    PolicySeverity severity = PolicySeverity::Medium;
};

struct SecurityPolicy {
    std::string id;
    std::string name;
    int version = 1;
    std::vector<PolicyRule> rules;
    int priority = 0;
    std::vector<std::string> targetGroups;
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point updatedAt;
    bool isGlobal = false;
};

struct PolicyViolation {
    std::string ruleId;
    PolicyRuleType ruleType;
    std::string detail;
    PolicySeverity severity;
};

struct PolicyCompliance {
    std::string endpointId;
    std::string policyId;
    bool compliant = true;
    std::vector<PolicyViolation> violations;
    std::chrono::system_clock::time_point lastChecked;
};

struct PolicyVersion {
    int version;
    SecurityPolicy snapshot;
    std::chrono::system_clock::time_point timestamp;
};

class IPolicyEngine {
public:
    virtual ~IPolicyEngine() = default;

    virtual std::string createPolicy(const SecurityPolicy& policy) = 0;
    virtual bool updatePolicy(const std::string& policyId, const SecurityPolicy& updated) = 0;
    virtual bool deletePolicy(const std::string& policyId) = 0;
    virtual std::optional<SecurityPolicy> getPolicy(const std::string& policyId) const = 0;
    virtual std::vector<SecurityPolicy> getPolicies() const = 0;

    virtual bool distributePolicy(const std::string& policyId, const std::vector<std::string>& groupIds) = 0;
    virtual PolicyCompliance checkCompliance(const std::string& endpointId, const std::string& policyId) = 0;
    virtual std::vector<PolicyCompliance> getComplianceStatus(const std::string& endpointId) const = 0;

    virtual std::vector<PolicyVersion> getPolicyHistory(const std::string& policyId) const = 0;
    virtual std::vector<SecurityPolicy> getInheritedPolicies(const std::string& endpointId,
                                                              const std::string& groupId) const = 0;
};

class PolicyEngine : public IPolicyEngine {
public:
    PolicyEngine();
    ~PolicyEngine() override = default;

    std::string createPolicy(const SecurityPolicy& policy) override;
    bool updatePolicy(const std::string& policyId, const SecurityPolicy& updated) override;
    bool deletePolicy(const std::string& policyId) override;
    std::optional<SecurityPolicy> getPolicy(const std::string& policyId) const override;
    std::vector<SecurityPolicy> getPolicies() const override;

    bool distributePolicy(const std::string& policyId, const std::vector<std::string>& groupIds) override;
    PolicyCompliance checkCompliance(const std::string& endpointId, const std::string& policyId) override;
    std::vector<PolicyCompliance> getComplianceStatus(const std::string& endpointId) const override;

    std::vector<PolicyVersion> getPolicyHistory(const std::string& policyId) const override;
    std::vector<SecurityPolicy> getInheritedPolicies(const std::string& endpointId,
                                                      const std::string& groupId) const override;

    // Set compliance state for testing/simulation
    void setEndpointCompliance(const std::string& endpointId, const std::string& policyId,
                                bool compliant, const std::vector<PolicyViolation>& violations = {});

private:
    std::string generateId() const;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, SecurityPolicy> policies_;
    std::unordered_map<std::string, std::vector<PolicyVersion>> policyHistory_;
    std::unordered_map<std::string, std::vector<PolicyCompliance>> complianceState_; // key: endpointId
    int nextId_ = 1;
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Fleet
