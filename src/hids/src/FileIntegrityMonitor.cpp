#include "hids/FileIntegrityMonitor.h"

#include <algorithm>
#include <chrono>
#include <sstream>

namespace ThreatOne::HIDS {

FileIntegrityMonitor::FileIntegrityMonitor()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("FileIntegrityMonitor")) {
    logger_.info("FileIntegrityMonitor initialized");
}

std::string FileIntegrityMonitor::generateEventId() {
    return "FIM-EVT-" + std::to_string(nextEventId_++);
}

std::string FileIntegrityMonitor::generateBaselineId() {
    return "FIM-BL-" + std::to_string(nextBaselineId_++);
}

std::string FileIntegrityMonitor::generateRuleId() {
    return "FIM-RULE-" + std::to_string(nextRuleId_++);
}

std::string FileIntegrityMonitor::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << time;
    return oss.str();
}

std::string FileIntegrityMonitor::createBaseline(const std::string& name,
    const std::unordered_map<std::string, std::string>& fileHashes) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (name.empty()) {
        logger_.error("Cannot create baseline with empty name");
        return "";
    }

    std::string id = generateBaselineId();
    BaselineInfo info;
    info.id = id;
    info.name = name;
    info.createdAt = getCurrentTimestamp();
    info.fileCount = fileHashes.size();
    info.status = "Active";

    baselines_[id] = info;
    baselineHashes_[id] = fileHashes;

    logger_.info("Created baseline '{}' ({}) with {} files", name, id, fileHashes.size());
    return id;
}

BaselineInfo FileIntegrityMonitor::getBaseline(const std::string& baselineId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = baselines_.find(baselineId);
    if (it != baselines_.end()) {
        return it->second;
    }
    return {"", "Not Found", "", 0, "Not created"};
}

BaselineInfo FileIntegrityMonitor::getLatestBaseline() const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (baselines_.empty()) {
        return {"", "No Baseline", "", 0, "Not created"};
    }
    return baselines_.rbegin()->second;
}

std::vector<BaselineInfo> FileIntegrityMonitor::listBaselines() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<BaselineInfo> result;
    result.reserve(baselines_.size());
    for (const auto& [id, info] : baselines_) {
        result.push_back(info);
    }
    return result;
}

bool FileIntegrityMonitor::deleteBaseline(const std::string& baselineId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = baselines_.find(baselineId);
    if (it == baselines_.end()) {
        return false;
    }
    baselines_.erase(it);
    baselineHashes_.erase(baselineId);
    logger_.info("Deleted baseline: {}", baselineId);
    return true;
}

std::vector<IntegrityEvent> FileIntegrityMonitor::compareToBaseline(
    const std::string& baselineId,
    const std::unordered_map<std::string, std::string>& currentHashes) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto hashIt = baselineHashes_.find(baselineId);
    if (hashIt == baselineHashes_.end()) {
        logger_.error("Baseline not found for comparison: {}", baselineId);
        return {};
    }

    std::vector<IntegrityEvent> events;
    const auto& baseHashes = hashIt->second;

    // Check for modified or deleted files
    for (const auto& [path, baseHash] : baseHashes) {
        auto currentIt = currentHashes.find(path);
        if (currentIt == currentHashes.end()) {
            IntegrityEvent event;
            event.id = generateEventId();
            event.path = path;
            event.changeType = "deleted";
            event.previousHash = baseHash;
            event.currentHash = "";
            event.timestamp = getCurrentTimestamp();
            events.push_back(event);
        } else if (currentIt->second != baseHash) {
            IntegrityEvent event;
            event.id = generateEventId();
            event.path = path;
            event.changeType = "modified";
            event.previousHash = baseHash;
            event.currentHash = currentIt->second;
            event.timestamp = getCurrentTimestamp();
            events.push_back(event);
        }
    }

    // Check for new files
    for (const auto& [path, hash] : currentHashes) {
        if (baseHashes.find(path) == baseHashes.end()) {
            IntegrityEvent event;
            event.id = generateEventId();
            event.path = path;
            event.changeType = "created";
            event.previousHash = "";
            event.currentHash = hash;
            event.timestamp = getCurrentTimestamp();
            events.push_back(event);
        }
    }

    // Store events
    for (const auto& event : events) {
        integrityEvents_.push_back(event);
    }

    logger_.info("Compared to baseline {}: {} changes", baselineId, events.size());
    return events;
}

void FileIntegrityMonitor::recordFileChange(const std::string& path,
    const std::string& oldHash, const std::string& newHash) {
    std::lock_guard<std::mutex> lock(mutex_);

    FileChange change;
    change.path = path;
    change.action = oldHash.empty() ? "created" : "modified";
    change.user = "system";
    change.size = 0;
    change.timestamp = getCurrentTimestamp();
    fileChanges_.push_back(change);

    if (!oldHash.empty() && oldHash != newHash) {
        IntegrityEvent event;
        event.id = generateEventId();
        event.path = path;
        event.changeType = "modified";
        event.previousHash = oldHash;
        event.currentHash = newHash;
        event.timestamp = getCurrentTimestamp();
        integrityEvents_.push_back(event);
    }

    currentFileHashes_[path] = newHash;
}

std::vector<IntegrityEvent> FileIntegrityMonitor::getIntegrityEvents() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return integrityEvents_;
}

std::vector<FileChange> FileIntegrityMonitor::getFileChanges() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return fileChanges_;
}

std::string FileIntegrityMonitor::addMonitoringRule(const MonitoringRule& rule) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (rule.path.empty()) {
        return "";
    }

    std::string id = generateRuleId();
    MonitoringRule newRule = rule;
    newRule.id = id;
    monitoringRules_[id] = newRule;

    logger_.info("Added monitoring rule: {} for path {}", id, rule.path);
    return id;
}

bool FileIntegrityMonitor::removeMonitoringRule(const std::string& ruleId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = monitoringRules_.find(ruleId);
    if (it == monitoringRules_.end()) {
        return false;
    }
    monitoringRules_.erase(it);
    return true;
}

std::vector<MonitoringRule> FileIntegrityMonitor::getMonitoringRules() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<MonitoringRule> result;
    result.reserve(monitoringRules_.size());
    for (const auto& [id, rule] : monitoringRules_) {
        result.push_back(rule);
    }
    return result;
}

bool FileIntegrityMonitor::addMonitoredPath(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (path.empty()) {
        return false;
    }

    if (std::find(monitoredPaths_.begin(), monitoredPaths_.end(), path) != monitoredPaths_.end()) {
        return false;
    }

    monitoredPaths_.push_back(path);
    logger_.info("Added monitored path: {}", path);
    return true;
}

bool FileIntegrityMonitor::removeMonitoredPath(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = std::find(monitoredPaths_.begin(), monitoredPaths_.end(), path);
    if (it == monitoredPaths_.end()) {
        return false;
    }
    monitoredPaths_.erase(it);
    return true;
}

std::vector<std::string> FileIntegrityMonitor::getMonitoredPaths() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return monitoredPaths_;
}

void FileIntegrityMonitor::updateFileHash(const std::string& path, const std::string& hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    currentFileHashes_[path] = hash;
}

std::string FileIntegrityMonitor::getFileHash(const std::string& path) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = currentFileHashes_.find(path);
    if (it != currentFileHashes_.end()) {
        return it->second;
    }
    return "";
}

std::unordered_map<std::string, std::string> FileIntegrityMonitor::getCurrentHashes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return currentFileHashes_;
}

uint64_t FileIntegrityMonitor::getTotalFilesMonitored() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return currentFileHashes_.size();
}

uint64_t FileIntegrityMonitor::getTotalEventsGenerated() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return integrityEvents_.size();
}

} // namespace ThreatOne::HIDS
