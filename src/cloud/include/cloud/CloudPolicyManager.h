#pragma once

#include "cloud/ICloudManager.h"
#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>

namespace ThreatOne::Cloud {

struct PolicyVersion {
    std::string policyId;
    int version = 1;
    std::string content;
    std::string createdAt;
    bool active = false;
};

class CloudPolicyManager {
public:
    CloudPolicyManager();
    ~CloudPolicyManager() = default;

    // Policy distribution
    std::string distributePolicy(const PolicyInfo& policy);
    [[nodiscard]] std::vector<PolicyInfo> getPolicies() const;

    // Acknowledgment tracking
    bool acknowledgePolicy(const std::string& policyId, const std::string& endpointId);
    [[nodiscard]] std::vector<std::string> getAcknowledgments(const std::string& policyId) const;
    [[nodiscard]] bool isPolicyAcknowledgedBy(const std::string& policyId, const std::string& endpointId) const;

    // Version management
    std::string createPolicyVersion(const std::string& policyId, const std::string& content);
    [[nodiscard]] std::vector<PolicyVersion> getPolicyVersions(const std::string& policyId) const;
    bool activatePolicyVersion(const std::string& policyId, int version);
    [[nodiscard]] int getActivePolicyVersion(const std::string& policyId) const;

    // Policy removal
    bool removePolicy(const std::string& policyId);

    // Metrics
    [[nodiscard]] size_t getPolicyCount() const;

private:
    std::string generatePolicyId();

    mutable std::mutex mutex_;
    std::map<std::string, PolicyInfo> policies_;
    std::map<std::string, std::vector<PolicyVersion>> policyVersions_;
    int nextPolicyId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Cloud
