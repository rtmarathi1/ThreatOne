#include "fleet/PolicyEngine.h"

#include <algorithm>
#include <sstream>
#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace ThreatOne::Fleet {

PolicyEngine::PolicyEngine()
    : logger_("PolicyEngine") {
    logger_.info("Policy Engine initialized");
}

std::string PolicyEngine::generateId() const {
    std::ostringstream oss;
    oss << "pol-" << nextId_;
    return oss.str();
}

std::string PolicyEngine::createPolicy(const SecurityPolicy& policy) {
    std::lock_guard<std::mutex> lock(mutex_);

    SecurityPolicy p = policy;
    if (p.id.empty()) {
        p.id = generateId();
        ++nextId_;
    }
    p.version = 1;
    p.createdAt = std::chrono::system_clock::now();
    p.updatedAt = p.createdAt;

    // Store initial version in history
    PolicyVersion pv;
    pv.version = p.version;
    pv.snapshot = p;
    pv.timestamp = p.createdAt;
    policyHistory_[p.id].push_back(pv);

    policies_[p.id] = p;
    logger_.info("Created policy: {} ({})", p.id, p.name);
    return p.id;
}

bool PolicyEngine::updatePolicy(const std::string& policyId, const SecurityPolicy& updated) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = policies_.find(policyId);
    if (it == policies_.end()) {
        return false;
    }

    SecurityPolicy p = updated;
    p.id = policyId;
    p.version = it->second.version + 1;
    p.createdAt = it->second.createdAt;
    p.updatedAt = std::chrono::system_clock::now();

    // Record version in history
    PolicyVersion pv;
    pv.version = p.version;
    pv.snapshot = p;
    pv.timestamp = p.updatedAt;
    policyHistory_[policyId].push_back(pv);

    it->second = p;
    logger_.info("Updated policy: {} to version {}", policyId, p.version);
    return true;
}

bool PolicyEngine::deletePolicy(const std::string& policyId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = policies_.find(policyId);
    if (it == policies_.end()) {
        return false;
    }

    policies_.erase(it);
    // Keep history for audit purposes
    logger_.info("Deleted policy: {}", policyId);
    return true;
}

std::optional<SecurityPolicy> PolicyEngine::getPolicy(const std::string& policyId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = policies_.find(policyId);
    if (it == policies_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<SecurityPolicy> PolicyEngine::getPolicies() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<SecurityPolicy> result;
    result.reserve(policies_.size());
    for (const auto& [id, policy] : policies_) {
        result.push_back(policy);
    }
    return result;
}

bool PolicyEngine::distributePolicy(const std::string& policyId, const std::vector<std::string>& groupIds) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = policies_.find(policyId);
    if (it == policies_.end()) {
        return false;
    }

    it->second.targetGroups = groupIds;
    it->second.updatedAt = std::chrono::system_clock::now();
    logger_.info("Distributed policy {} to {} groups", policyId, groupIds.size());
    return true;
}

PolicyCompliance PolicyEngine::checkCompliance(const std::string& endpointId, const std::string& policyId) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check if we have stored compliance state
    auto epIt = complianceState_.find(endpointId);
    if (epIt != complianceState_.end()) {
        for (const auto& compliance : epIt->second) {
            if (compliance.policyId == policyId) {
                return compliance;
            }
        }
    }

    // Default: compliant if no specific state set
    PolicyCompliance result;
    result.endpointId = endpointId;
    result.policyId = policyId;
    result.compliant = true;
    result.lastChecked = std::chrono::system_clock::now();
    return result;
}

std::vector<PolicyCompliance> PolicyEngine::getComplianceStatus(const std::string& endpointId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = complianceState_.find(endpointId);
    if (it == complianceState_.end()) {
        return {};
    }
    return it->second;
}

std::vector<PolicyVersion> PolicyEngine::getPolicyHistory(const std::string& policyId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = policyHistory_.find(policyId);
    if (it == policyHistory_.end()) {
        return {};
    }
    return it->second;
}

std::vector<SecurityPolicy> PolicyEngine::getInheritedPolicies(const std::string& endpointId,
                                                                const std::string& groupId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<SecurityPolicy> inherited;

    // Collect global policies (highest priority inheritance)
    for (const auto& [id, policy] : policies_) {
        if (policy.isGlobal) {
            inherited.push_back(policy);
        }
    }

    // Collect group-level policies
    if (!groupId.empty()) {
        for (const auto& [id, policy] : policies_) {
            if (policy.isGlobal) {
                continue; // Already added
            }
            for (const auto& targetGroup : policy.targetGroups) {
                if (targetGroup == groupId) {
                    inherited.push_back(policy);
                    break;
                }
            }
        }
    }

    // Sort by priority (higher priority first)
    std::sort(inherited.begin(), inherited.end(),
              [](const SecurityPolicy& a, const SecurityPolicy& b) {
                  return a.priority > b.priority;
              });

    return inherited;
}

void PolicyEngine::setEndpointCompliance(const std::string& endpointId, const std::string& policyId,
                                          bool compliant, const std::vector<PolicyViolation>& violations) {
    std::lock_guard<std::mutex> lock(mutex_);

    PolicyCompliance compliance;
    compliance.endpointId = endpointId;
    compliance.policyId = policyId;
    compliance.compliant = compliant;
    compliance.violations = violations;
    compliance.lastChecked = std::chrono::system_clock::now();

    auto& epCompliance = complianceState_[endpointId];

    // Update existing or add new
    bool found = false;
    for (auto& existing : epCompliance) {
        if (existing.policyId == policyId) {
            existing = compliance;
            found = true;
            break;
        }
    }
    if (!found) {
        epCompliance.push_back(compliance);
    }
}

} // namespace ThreatOne::Fleet
