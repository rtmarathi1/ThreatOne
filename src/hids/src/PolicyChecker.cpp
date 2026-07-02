#include "hids/PolicyChecker.h"

#include <chrono>
#include <sstream>

namespace ThreatOne::HIDS {

PolicyChecker::PolicyChecker()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("PolicyChecker")) {
    logger_.info("PolicyChecker initialized");
}

std::string PolicyChecker::generatePolicyId() {
    return "POL-" + std::to_string(nextPolicyId_++);
}

std::string PolicyChecker::generateViolationId() {
    return "PVIOL-" + std::to_string(nextViolationId_++);
}

std::string PolicyChecker::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << time;
    return oss.str();
}

std::string PolicyChecker::addPolicy(const SecurityPolicy& policy) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (policy.name.empty()) {
        logger_.error("Cannot add policy with empty name");
        return "";
    }

    std::string id = generatePolicyId();
    SecurityPolicy newPolicy = policy;
    newPolicy.id = id;
    policies_[id] = newPolicy;

    logger_.info("Added security policy: {} ({})", policy.name, id);
    return id;
}

bool PolicyChecker::removePolicy(const std::string& policyId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = policies_.find(policyId);
    if (it == policies_.end()) {
        return false;
    }
    policies_.erase(it);
    return true;
}

bool PolicyChecker::enablePolicy(const std::string& policyId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = policies_.find(policyId);
    if (it == policies_.end()) {
        return false;
    }
    it->second.enabled = true;
    return true;
}

bool PolicyChecker::disablePolicy(const std::string& policyId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = policies_.find(policyId);
    if (it == policies_.end()) {
        return false;
    }
    it->second.enabled = false;
    return true;
}

std::vector<SecurityPolicy> PolicyChecker::getPolicies() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<SecurityPolicy> result;
    result.reserve(policies_.size());
    for (const auto& [id, policy] : policies_) {
        result.push_back(policy);
    }
    return result;
}

SecurityPolicy PolicyChecker::getPolicy(const std::string& policyId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = policies_.find(policyId);
    if (it != policies_.end()) {
        return it->second;
    }
    return {};
}

PolicyCheckResult PolicyChecker::evaluatePolicy(const SecurityPolicy& policy) const {
    PolicyCheckResult result;
    result.policyId = policy.id;
    result.policyName = policy.name;
    result.expectedValue = policy.expectedValue;
    result.checkedAt = getCurrentTimestamp();

    // Simulate policy evaluation based on category
    switch (policy.category) {
        case PolicyCategory::FilePermission:
            result.actualValue = "0644";
            result.compliant = (result.actualValue == policy.expectedValue);
            if (!result.compliant) {
                result.detail = "File permission mismatch at " + policy.path;
            }
            break;
        case PolicyCategory::ServiceConfig:
            result.actualValue = "enabled";
            result.compliant = (result.actualValue == policy.expectedValue);
            if (!result.compliant) {
                result.detail = "Service configuration does not match policy";
            }
            break;
        case PolicyCategory::UserAccount:
            result.actualValue = "active";
            result.compliant = (result.actualValue == policy.expectedValue);
            if (!result.compliant) {
                result.detail = "User account state does not match policy";
            }
            break;
        case PolicyCategory::NetworkConfig:
            result.actualValue = "restricted";
            result.compliant = (result.actualValue == policy.expectedValue);
            if (!result.compliant) {
                result.detail = "Network configuration does not match policy";
            }
            break;
        case PolicyCategory::AuditConfig:
            result.actualValue = "enabled";
            result.compliant = (result.actualValue == policy.expectedValue);
            if (!result.compliant) {
                result.detail = "Audit configuration does not match policy";
            }
            break;
        case PolicyCategory::SystemHardening:
            result.actualValue = "hardened";
            result.compliant = (result.actualValue == policy.expectedValue);
            if (!result.compliant) {
                result.detail = "System hardening configuration does not match policy";
            }
            break;
    }

    return result;
}

std::vector<PolicyCheckResult> PolicyChecker::runAllChecks() {
    std::lock_guard<std::mutex> lock(mutex_);

    lastCheckResults_.clear();
    lastCheckTime_ = getCurrentTimestamp();

    for (const auto& [id, policy] : policies_) {
        if (!policy.enabled) continue;

        auto result = evaluatePolicy(policy);
        lastCheckResults_.push_back(result);
        totalChecksRun_++;

        if (!result.compliant) {
            PolicyViolation violation;
            violation.id = generateViolationId();
            violation.policyName = policy.name;
            violation.description = result.detail;
            violation.severity = policy.severity;
            violation.path = policy.path;
            violation.timestamp = getCurrentTimestamp();
            violations_.push_back(violation);
        }
    }

    logger_.info("Policy check completed: {} checks run", lastCheckResults_.size());
    return lastCheckResults_;
}

PolicyCheckResult PolicyChecker::checkPolicy(const std::string& policyId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = policies_.find(policyId);
    if (it == policies_.end()) {
        return {};
    }

    auto result = evaluatePolicy(it->second);
    totalChecksRun_++;
    return result;
}

std::vector<PolicyViolation> PolicyChecker::getViolations() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return violations_;
}

void PolicyChecker::addViolation(const PolicyViolation& violation) {
    std::lock_guard<std::mutex> lock(mutex_);
    violations_.push_back(violation);
}

PolicyComplianceSummary PolicyChecker::getComplianceSummary() const {
    std::lock_guard<std::mutex> lock(mutex_);

    PolicyComplianceSummary summary;
    summary.totalPolicies = lastCheckResults_.size();
    summary.lastCheckTime = lastCheckTime_;

    for (const auto& result : lastCheckResults_) {
        if (result.compliant) {
            summary.compliant++;
        } else {
            summary.nonCompliant++;
        }
    }

    if (summary.totalPolicies > 0) {
        summary.compliancePercent =
            (static_cast<double>(summary.compliant) / static_cast<double>(summary.totalPolicies)) * 100.0;
    }

    return summary;
}

void PolicyChecker::clearViolations() {
    std::lock_guard<std::mutex> lock(mutex_);
    violations_.clear();
}

uint64_t PolicyChecker::getTotalChecksRun() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return totalChecksRun_;
}

} // namespace ThreatOne::HIDS
