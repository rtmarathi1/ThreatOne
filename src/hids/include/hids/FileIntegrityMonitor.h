#pragma once

#include "hids/IHIDSEngine.h"
#include "core/Logger.h"

#include <mutex>
#include <map>
#include <unordered_map>
#include <string>
#include <vector>
#include <cstdint>
#include <functional>

namespace ThreatOne::HIDS {

enum class HashAlgorithm {
    SHA256,
    SHA512,
    MD5
};

struct FileHashEntry {
    std::string path;
    std::string hash;
    HashAlgorithm algorithm = HashAlgorithm::SHA256;
    uint64_t fileSize = 0;
    std::string lastModified;
    std::string permissions;
};

struct MonitoringRule {
    std::string id;
    std::string path;
    bool recursive = true;
    std::vector<std::string> includePatterns;
    std::vector<std::string> excludePatterns;
    bool realTime = false;
};

class FileIntegrityMonitor {
public:
    FileIntegrityMonitor();
    ~FileIntegrityMonitor() = default;

    // Baseline management
    std::string createBaseline(const std::string& name,
                               const std::unordered_map<std::string, std::string>& fileHashes);
    [[nodiscard]] BaselineInfo getBaseline(const std::string& baselineId) const;
    [[nodiscard]] BaselineInfo getLatestBaseline() const;
    [[nodiscard]] std::vector<BaselineInfo> listBaselines() const;
    bool deleteBaseline(const std::string& baselineId);

    // Change detection
    std::vector<IntegrityEvent> compareToBaseline(
        const std::string& baselineId,
        const std::unordered_map<std::string, std::string>& currentHashes);
    void recordFileChange(const std::string& path, const std::string& oldHash,
                          const std::string& newHash);
    [[nodiscard]] std::vector<IntegrityEvent> getIntegrityEvents() const;
    [[nodiscard]] std::vector<FileChange> getFileChanges() const;

    // Monitoring rules
    std::string addMonitoringRule(const MonitoringRule& rule);
    bool removeMonitoringRule(const std::string& ruleId);
    [[nodiscard]] std::vector<MonitoringRule> getMonitoringRules() const;

    // Path management
    bool addMonitoredPath(const std::string& path);
    bool removeMonitoredPath(const std::string& path);
    [[nodiscard]] std::vector<std::string> getMonitoredPaths() const;

    // File hash tracking
    void updateFileHash(const std::string& path, const std::string& hash);
    [[nodiscard]] std::string getFileHash(const std::string& path) const;
    [[nodiscard]] std::unordered_map<std::string, std::string> getCurrentHashes() const;

    // Stats
    [[nodiscard]] uint64_t getTotalFilesMonitored() const;
    [[nodiscard]] uint64_t getTotalEventsGenerated() const;

private:
    std::string generateEventId();
    std::string generateBaselineId();
    std::string generateRuleId();
    std::string getCurrentTimestamp() const;

    mutable std::mutex mutex_;

    // Baselines
    std::map<std::string, BaselineInfo> baselines_;
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> baselineHashes_;

    // Current state
    std::unordered_map<std::string, std::string> currentFileHashes_;
    std::vector<std::string> monitoredPaths_;
    std::map<std::string, MonitoringRule> monitoringRules_;

    // Events
    std::vector<IntegrityEvent> integrityEvents_;
    std::vector<FileChange> fileChanges_;

    int nextEventId_ = 1;
    int nextBaselineId_ = 1;
    int nextRuleId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::HIDS
