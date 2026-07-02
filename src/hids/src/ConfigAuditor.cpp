#include "hids/ConfigAuditor.h"
#include <mutex>

#include <chrono>
#include <sstream>

namespace ThreatOne::HIDS {

ConfigAuditor::ConfigAuditor()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("ConfigAuditor")) {
    logger_.info("ConfigAuditor initialized");
}

std::string ConfigAuditor::generateConfigId() {
    return "CFG-" + std::to_string(nextConfigId_++);
}

std::string ConfigAuditor::generateResultId() {
    return "AUDIT-" + std::to_string(nextResultId_++);
}

std::string ConfigAuditor::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << time;
    return oss.str();
}

std::string ConfigAuditor::addConfigFile(const ConfigFile& config) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (config.path.empty()) {
        logger_.error("Cannot add config file with empty path");
        return "";
    }

    std::string id = generateConfigId();
    ConfigFile newConfig = config;
    newConfig.id = id;
    configFiles_[id] = newConfig;

    logger_.info("Added config file for auditing: {} ({})", config.path, id);
    return id;
}

bool ConfigAuditor::removeConfigFile(const std::string& configId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = configFiles_.find(configId);
    if (it == configFiles_.end()) {
        return false;
    }
    configFiles_.erase(it);
    return true;
}

bool ConfigAuditor::updateExpectedHash(const std::string& configId, const std::string& hash) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = configFiles_.find(configId);
    if (it == configFiles_.end()) {
        return false;
    }
    it->second.expectedHash = hash;
    return true;
}

std::vector<ConfigFile> ConfigAuditor::getConfigFiles() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ConfigFile> result;
    result.reserve(configFiles_.size());
    for (const auto& [id, config] : configFiles_) {
        result.push_back(config);
    }
    return result;
}

ConfigFile ConfigAuditor::getConfigFile(const std::string& configId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = configFiles_.find(configId);
    if (it != configFiles_.end()) {
        return it->second;
    }
    return {};
}

ConfigAuditResult ConfigAuditor::evaluateConfig(const ConfigFile& config) const {
    ConfigAuditResult result;
    result.id = "AUDIT-" + std::to_string(const_cast<int&>(nextResultId_)++);
    result.configFileId = config.id;
    result.path = config.path;
    result.auditedAt = getCurrentTimestamp();

    if (config.expectedHash.empty()) {
        // No expected hash set - cannot verify
        result.compliant = true;
        result.issue = "";
        result.severity = ConfigSeverity::Info;
        result.recommendation = "Set expected hash for baseline verification";
    } else if (config.currentHash.empty()) {
        // No current hash - file may not have been scanned
        result.compliant = false;
        result.issue = "Config file has not been scanned";
        result.severity = ConfigSeverity::Medium;
        result.recommendation = "Run file scan to update current hash";
    } else if (config.currentHash != config.expectedHash) {
        // Hash mismatch - unauthorized change
        result.compliant = false;
        result.issue = "Config file hash mismatch - possible unauthorized change";
        result.severity = ConfigSeverity::High;
        result.recommendation = "Investigate change and update baseline if authorized";
    } else {
        result.compliant = true;
        result.issue = "";
        result.severity = ConfigSeverity::Info;
    }

    return result;
}

std::vector<ConfigAuditResult> ConfigAuditor::runAudit() {
    std::lock_guard<std::mutex> lock(mutex_);

    auditResults_.clear();
    lastAuditTime_ = getCurrentTimestamp();

    for (const auto& [id, config] : configFiles_) {
        if (!config.monitored) continue;

        auto result = evaluateConfig(config);
        auditResults_.push_back(result);
    }

    totalAuditsRun_++;
    logger_.info("Config audit completed: {} files audited", auditResults_.size());
    return auditResults_;
}

ConfigAuditResult ConfigAuditor::auditConfigFile(const std::string& configId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = configFiles_.find(configId);
    if (it == configFiles_.end()) {
        return {};
    }

    return evaluateConfig(it->second);
}

std::vector<ConfigAuditResult> ConfigAuditor::getAuditResults() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return auditResults_;
}

void ConfigAuditor::updateCurrentHash(const std::string& configId, const std::string& hash) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = configFiles_.find(configId);
    if (it != configFiles_.end()) {
        it->second.currentHash = hash;
    }
}

std::vector<ConfigFile> ConfigAuditor::getChangedConfigs() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ConfigFile> changed;
    for (const auto& [id, config] : configFiles_) {
        if (!config.expectedHash.empty() && !config.currentHash.empty() &&
            config.currentHash != config.expectedHash) {
            changed.push_back(config);
        }
    }
    return changed;
}

bool ConfigAuditor::acknowledgeChange(const std::string& configId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = configFiles_.find(configId);
    if (it == configFiles_.end()) {
        return false;
    }

    // Accept current hash as the new expected hash
    it->second.expectedHash = it->second.currentHash;
    logger_.info("Acknowledged config change for: {}", it->second.path);
    return true;
}

ConfigAuditSummary ConfigAuditor::getSummary() const {
    std::lock_guard<std::mutex> lock(mutex_);

    ConfigAuditSummary summary;
    summary.totalConfigs = configFiles_.size();
    summary.lastAuditTime = lastAuditTime_;

    for (const auto& result : auditResults_) {
        if (result.compliant) {
            summary.compliant++;
        } else {
            summary.nonCompliant++;
        }
    }

    for (const auto& [id, config] : configFiles_) {
        if (!config.expectedHash.empty() && !config.currentHash.empty() &&
            config.currentHash != config.expectedHash) {
            summary.changed++;
        }
    }

    if (summary.totalConfigs > 0) {
        summary.compliancePercent =
            (static_cast<double>(summary.compliant) / static_cast<double>(summary.totalConfigs)) * 100.0;
    }

    return summary;
}

void ConfigAuditor::clearResults() {
    std::lock_guard<std::mutex> lock(mutex_);
    auditResults_.clear();
}

uint64_t ConfigAuditor::getTotalAuditsRun() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return totalAuditsRun_;
}

} // namespace ThreatOne::HIDS
