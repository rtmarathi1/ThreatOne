#pragma once

#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>
#include <cstdint>

namespace ThreatOne::HIDS {

enum class ConfigSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical
};

struct ConfigFile {
    std::string id;
    std::string path;
    std::string description;
    std::string expectedHash;
    std::string currentHash;
    bool monitored = true;
};

struct ConfigAuditResult {
    std::string id;
    std::string configFileId;
    std::string path;
    bool compliant = false;
    std::string issue;
    ConfigSeverity severity = ConfigSeverity::Medium;
    std::string recommendation;
    std::string auditedAt;
};

struct ConfigAuditSummary {
    uint64_t totalConfigs = 0;
    uint64_t compliant = 0;
    uint64_t nonCompliant = 0;
    uint64_t changed = 0;
    double compliancePercent = 0.0;
    std::string lastAuditTime;
};

class ConfigAuditor {
public:
    ConfigAuditor();
    ~ConfigAuditor() = default;

    // Config file management
    std::string addConfigFile(const ConfigFile& config);
    bool removeConfigFile(const std::string& configId);
    bool updateExpectedHash(const std::string& configId, const std::string& hash);
    [[nodiscard]] std::vector<ConfigFile> getConfigFiles() const;
    [[nodiscard]] ConfigFile getConfigFile(const std::string& configId) const;

    // Auditing
    std::vector<ConfigAuditResult> runAudit();
    ConfigAuditResult auditConfigFile(const std::string& configId);
    [[nodiscard]] std::vector<ConfigAuditResult> getAuditResults() const;

    // Change detection
    void updateCurrentHash(const std::string& configId, const std::string& hash);
    [[nodiscard]] std::vector<ConfigFile> getChangedConfigs() const;
    bool acknowledgeChange(const std::string& configId);

    // Summary
    [[nodiscard]] ConfigAuditSummary getSummary() const;
    void clearResults();

    // Stats
    [[nodiscard]] uint64_t getTotalAuditsRun() const;

private:
    std::string generateConfigId();
    std::string generateResultId();
    std::string getCurrentTimestamp() const;
    ConfigAuditResult evaluateConfig(const ConfigFile& config) const;

    mutable std::mutex mutex_;

    std::map<std::string, ConfigFile> configFiles_;
    std::vector<ConfigAuditResult> auditResults_;
    std::string lastAuditTime_;

    uint64_t totalAuditsRun_ = 0;

    int nextConfigId_ = 1;
    int nextResultId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::HIDS
