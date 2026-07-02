#include "cloud/CloudPolicyManager.h"
#include <mutex>

#include <algorithm>

namespace ThreatOne::Cloud {

CloudPolicyManager::CloudPolicyManager()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("CloudPolicyManager")) {
    logger_.info("CloudPolicyManager initialized");
}

std::string CloudPolicyManager::generatePolicyId() {
    return "POL-" + std::to_string(nextPolicyId_++);
}

std::string CloudPolicyManager::distributePolicy(const PolicyInfo& policy) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = generatePolicyId();
    PolicyInfo stored = policy;
    stored.id = id;
    stored.distributedAt = "now";
    policies_[id] = stored;

    // Create initial version
    PolicyVersion pv;
    pv.policyId = id;
    pv.version = stored.version;
    pv.content = stored.content;
    pv.createdAt = "now";
    pv.active = true;
    policyVersions_[id].push_back(pv);

    logger_.info("Distributed policy: id={}, name={}, version={}", id, policy.name, policy.version);
    return id;
}

std::vector<PolicyInfo> CloudPolicyManager::getPolicies() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<PolicyInfo> result;
    result.reserve(policies_.size());
    for (const auto& [id, policy] : policies_) {
        result.push_back(policy);
    }
    return result;
}

bool CloudPolicyManager::acknowledgePolicy(const std::string& policyId, const std::string& endpointId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = policies_.find(policyId);
    if (it == policies_.end()) {
        logger_.warn("acknowledgePolicy failed: policy {} not found", policyId);
        return false;
    }

    // Check if already acknowledged
    auto& ackList = it->second.acknowledgedBy;
    if (std::find(ackList.begin(), ackList.end(), endpointId) != ackList.end()) {
        logger_.info("Policy {} already acknowledged by {}", policyId, endpointId);
        return true;
    }

    ackList.push_back(endpointId);
    logger_.info("Policy {} acknowledged by endpoint {}", policyId, endpointId);
    return true;
}

std::vector<std::string> CloudPolicyManager::getAcknowledgments(const std::string& policyId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = policies_.find(policyId);
    if (it == policies_.end()) {
        return {};
    }
    return it->second.acknowledgedBy;
}

bool CloudPolicyManager::isPolicyAcknowledgedBy(const std::string& policyId, const std::string& endpointId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = policies_.find(policyId);
    if (it == policies_.end()) {
        return false;
    }

    const auto& ackList = it->second.acknowledgedBy;
    return std::find(ackList.begin(), ackList.end(), endpointId) != ackList.end();
}

std::string CloudPolicyManager::createPolicyVersion(const std::string& policyId, const std::string& content) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = policies_.find(policyId);
    if (it == policies_.end()) {
        logger_.warn("createPolicyVersion: policy {} not found", policyId);
        return "";
    }

    auto& versions = policyVersions_[policyId];
    int nextVersion = versions.empty() ? 1 : versions.back().version + 1;

    PolicyVersion pv;
    pv.policyId = policyId;
    pv.version = nextVersion;
    pv.content = content;
    pv.createdAt = "now";
    pv.active = false;
    versions.push_back(pv);

    logger_.info("Created policy version: policy={}, version={}", policyId, nextVersion);
    return policyId;
}

std::vector<PolicyVersion> CloudPolicyManager::getPolicyVersions(const std::string& policyId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = policyVersions_.find(policyId);
    if (it == policyVersions_.end()) {
        return {};
    }
    return it->second;
}

bool CloudPolicyManager::activatePolicyVersion(const std::string& policyId, int version) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = policyVersions_.find(policyId);
    if (it == policyVersions_.end()) {
        return false;
    }

    bool found = false;
    for (auto& pv : it->second) {
        if (pv.version == version) {
            pv.active = true;
            found = true;
        } else {
            pv.active = false;
        }
    }

    if (found) {
        // Update main policy version
        auto policyIt = policies_.find(policyId);
        if (policyIt != policies_.end()) {
            policyIt->second.version = version;
        }
        logger_.info("Activated policy version: policy={}, version={}", policyId, version);
    }

    return found;
}

int CloudPolicyManager::getActivePolicyVersion(const std::string& policyId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = policyVersions_.find(policyId);
    if (it == policyVersions_.end()) {
        return 0;
    }

    for (const auto& pv : it->second) {
        if (pv.active) {
            return pv.version;
        }
    }
    return 0;
}

bool CloudPolicyManager::removePolicy(const std::string& policyId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = policies_.find(policyId);
    if (it == policies_.end()) {
        logger_.warn("removePolicy: policy {} not found", policyId);
        return false;
    }

    policies_.erase(it);
    policyVersions_.erase(policyId);
    logger_.info("Removed policy: {}", policyId);
    return true;
}

size_t CloudPolicyManager::getPolicyCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return policies_.size();
}

} // namespace ThreatOne::Cloud
