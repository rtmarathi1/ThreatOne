#include "hids/HIDSEngine.h"

#include <algorithm>
#include <chrono>
#include <regex>
#include <sstream>
#include <mutex>
#include <string>
#include <vector>

namespace ThreatOne::HIDS {

HIDSEngine::HIDSEngine()
    : logger_("HIDSEngine") {
    logger_.info("HIDS Engine initialized");
}

std::string HIDSEngine::generateEventId() {
    std::ostringstream oss;
    oss << "EVT-" << nextEventId_;
    ++nextEventId_;
    return oss.str();
}

std::string HIDSEngine::generateBaselineId() {
    std::ostringstream oss;
    oss << "BL-" << nextBaselineId_;
    ++nextBaselineId_;
    return oss.str();
}

std::string HIDSEngine::generatePatternId() {
    std::ostringstream oss;
    oss << "PAT-" << nextPatternId_;
    ++nextPatternId_;
    return oss.str();
}

std::string HIDSEngine::generateIndicatorId() {
    std::ostringstream oss;
    oss << "RKI-" << nextIndicatorId_;
    ++nextIndicatorId_;
    return oss.str();
}

std::string HIDSEngine::generateLogEntryId() {
    std::ostringstream oss;
    oss << "LOG-" << nextLogEntryId_;
    ++nextLogEntryId_;
    return oss.str();
}

std::string HIDSEngine::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << time;
    return oss.str();
}

bool HIDSEngine::matchesPattern(const std::string& text, const std::string& pattern) const {
    try {
        std::regex re(pattern);
        return std::regex_search(text, re);
    } catch (const std::regex_error&) {
        return false;
    }
}

bool HIDSEngine::startMonitoring() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (status_ == MonitoringStatus::Active) {
        logger_.warn("Monitoring is already active");
        return false;
    }

    status_ = MonitoringStatus::Active;
    logger_.info("Monitoring started");
    return true;
}

bool HIDSEngine::stopMonitoring() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (status_ == MonitoringStatus::Stopped) {
        logger_.warn("Monitoring is already stopped");
        return false;
    }

    status_ = MonitoringStatus::Stopped;
    logger_.info("Monitoring stopped");
    return true;
}

MonitoringStatus HIDSEngine::getMonitoringStatus() {
    std::lock_guard<std::mutex> lock(mutex_);
    return status_;
}

bool HIDSEngine::setMonitoringConfig(const MonitoringConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);

    config_ = config;

    // Update monitored paths from config
    for (const auto& path : config.paths) {
        if (std::find(monitoredPaths_.begin(), monitoredPaths_.end(), path) == monitoredPaths_.end()) {
            monitoredPaths_.push_back(path);
        }
    }

    logger_.info("Monitoring config updated: {} paths, interval={}s",
                 config.paths.size(), config.checkIntervalSeconds);
    return true;
}

std::vector<IntegrityEvent> HIDSEngine::getIntegrityEvents() {
    std::lock_guard<std::mutex> lock(mutex_);
    return integrityEvents_;
}

std::vector<FileChange> HIDSEngine::getFileChanges() {
    std::lock_guard<std::mutex> lock(mutex_);
    return fileChanges_;
}

std::vector<PolicyViolation> HIDSEngine::getPolicyViolations() {
    std::lock_guard<std::mutex> lock(mutex_);
    return policyViolations_;
}

BaselineInfo HIDSEngine::getBaseline() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (baselines_.empty()) {
        return {"", "No Baseline", "", 0, "Not created"};
    }

    // Return the most recent baseline
    auto it = baselines_.rbegin();
    return it->second;
}

std::string HIDSEngine::createBaseline(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (name.empty()) {
        logger_.error("Cannot create baseline: empty name");
        return "";
    }

    std::string baselineId = generateBaselineId();

    BaselineInfo info;
    info.id = baselineId;
    info.name = name;
    info.createdAt = getCurrentTimestamp();
    info.fileCount = currentFileHashes_.size();
    info.status = "Active";

    baselines_[baselineId] = info;

    // Snapshot current file hashes for this baseline
    baselineHashes_[baselineId] = currentFileHashes_;

    logger_.info("Created baseline: {} ({}) with {} files", name, baselineId, info.fileCount);
    return baselineId;
}

std::vector<IntegrityEvent> HIDSEngine::compareToBaseline(const std::string& baselineId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto baselineIt = baselines_.find(baselineId);
    if (baselineIt == baselines_.end()) {
        logger_.error("Baseline not found: {}", baselineId);
        return {};
    }

    auto hashesIt = baselineHashes_.find(baselineId);
    if (hashesIt == baselineHashes_.end()) {
        return {};
    }

    std::vector<IntegrityEvent> events;
    const auto& baseHashes = hashesIt->second;

    // Check for modified files
    for (const auto& [path, baseHash] : baseHashes) {
        auto currentIt = currentFileHashes_.find(path);
        if (currentIt == currentFileHashes_.end()) {
            // File was deleted
            IntegrityEvent event;
            event.id = generateEventId();
            event.path = path;
            event.changeType = "deleted";
            event.previousHash = baseHash;
            event.currentHash = "";
            event.timestamp = getCurrentTimestamp();
            events.push_back(event);
        } else if (currentIt->second != baseHash) {
            // File was modified
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
    for (const auto& [path, hash] : currentFileHashes_) {
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

    // Store the integrity events
    for (const auto& event : events) {
        integrityEvents_.push_back(event);
    }

    logger_.info("Compared to baseline {}: {} changes detected", baselineId, events.size());
    return events;
}

bool HIDSEngine::addMonitoredPath(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (path.empty()) {
        logger_.error("Cannot add monitored path: empty path");
        return false;
    }

    // Check for duplicates
    if (std::find(monitoredPaths_.begin(), monitoredPaths_.end(), path) != monitoredPaths_.end()) {
        logger_.warn("Path already monitored: {}", path);
        return false;
    }

    monitoredPaths_.push_back(path);
    logger_.info("Added monitored path: {}", path);
    return true;
}

bool HIDSEngine::removeMonitoredPath(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = std::find(monitoredPaths_.begin(), monitoredPaths_.end(), path);
    if (it == monitoredPaths_.end()) {
        logger_.error("Cannot remove: path {} not monitored", path);
        return false;
    }

    monitoredPaths_.erase(it);
    logger_.info("Removed monitored path: {}", path);
    return true;
}

std::string HIDSEngine::addLogPattern(const LogPattern& pattern) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (pattern.pattern.empty()) {
        logger_.error("Cannot add log pattern: empty pattern");
        return "";
    }

    // Validate regex
    try {
        std::regex re(pattern.pattern);
        (void)re;
    } catch (const std::regex_error&) {
        logger_.error("Cannot add log pattern: invalid regex");
        return "";
    }

    std::string patternId = generatePatternId();

    LogPattern newPattern = pattern;
    newPattern.id = patternId;

    logPatterns_[patternId] = newPattern;
    logger_.info("Added log pattern: {} ({})", newPattern.name, patternId);
    return patternId;
}

std::vector<LogPattern> HIDSEngine::getLogPatterns() {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<LogPattern> result;
    result.reserve(logPatterns_.size());
    for (const auto& [id, pattern] : logPatterns_) {
        result.push_back(pattern);
    }
    return result;
}

std::vector<SystemLogEntry> HIDSEngine::getMatchedLogEntries() {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<SystemLogEntry> matched;
    for (const auto& entry : logEntries_) {
        if (entry.matched) {
            matched.push_back(entry);
        }
    }
    return matched;
}

bool HIDSEngine::runRootkitScan() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (status_ != MonitoringStatus::Active) {
        logger_.warn("Cannot run rootkit scan: monitoring not active");
        return false;
    }

    // Clear previous indicators
    rootkitIndicators_.clear();

    // Simulate rootkit scan - check for hidden processes
    {
        RootkitIndicator indicator;
        indicator.id = generateIndicatorId();
        indicator.type = RootkitType::HiddenProcess;
        indicator.description = "Scanned for hidden processes in process table";
        indicator.evidence = "No hidden processes detected";
        indicator.severity = "info";
        indicator.detectedAt = getCurrentTimestamp();
        rootkitIndicators_.push_back(indicator);
    }

    // Check for hidden files
    {
        RootkitIndicator indicator;
        indicator.id = generateIndicatorId();
        indicator.type = RootkitType::HiddenFile;
        indicator.description = "Scanned filesystem for hidden files";
        indicator.evidence = "No hidden files detected";
        indicator.severity = "info";
        indicator.detectedAt = getCurrentTimestamp();
        rootkitIndicators_.push_back(indicator);
    }

    // Check kernel modules
    {
        RootkitIndicator indicator;
        indicator.id = generateIndicatorId();
        indicator.type = RootkitType::KernelModule;
        indicator.description = "Checked loaded kernel modules";
        indicator.evidence = "No suspicious kernel modules detected";
        indicator.severity = "info";
        indicator.detectedAt = getCurrentTimestamp();
        rootkitIndicators_.push_back(indicator);
    }

    // Check syscall hooks
    {
        RootkitIndicator indicator;
        indicator.id = generateIndicatorId();
        indicator.type = RootkitType::SyscallHook;
        indicator.description = "Checked system call table for hooks";
        indicator.evidence = "No syscall hooks detected";
        indicator.severity = "info";
        indicator.detectedAt = getCurrentTimestamp();
        rootkitIndicators_.push_back(indicator);
    }

    logger_.info("Rootkit scan completed: {} indicators generated", rootkitIndicators_.size());
    return true;
}

std::vector<RootkitIndicator> HIDSEngine::getRootkitIndicators() {
    std::lock_guard<std::mutex> lock(mutex_);
    return rootkitIndicators_;
}

void HIDSEngine::simulateFileChange(const std::string& path, const std::string& newHash) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string oldHash;
    auto it = currentFileHashes_.find(path);
    if (it != currentFileHashes_.end()) {
        oldHash = it->second;
    }

    currentFileHashes_[path] = newHash;

    // Record the file change
    FileChange change;
    change.path = path;
    change.action = oldHash.empty() ? "created" : "modified";
    change.user = "system";
    change.size = 0;
    change.timestamp = getCurrentTimestamp();
    fileChanges_.push_back(change);

    // Generate integrity event if hash changed
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

    logger_.info("File change simulated: {} ({}->{})", path, oldHash, newHash);
}

void HIDSEngine::ingestLogEntry(const SystemLogEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);

    SystemLogEntry newEntry = entry;
    if (newEntry.id.empty()) {
        newEntry.id = generateLogEntryId();
    }
    if (newEntry.timestamp.empty()) {
        newEntry.timestamp = getCurrentTimestamp();
    }

    // Check against patterns
    for (const auto& [patId, pattern] : logPatterns_) {
        if (!pattern.enabled) continue;

        if (matchesPattern(newEntry.message, pattern.pattern)) {
            newEntry.matched = true;
            newEntry.matchedPatternId = patId;
            break;
        }
    }

    logEntries_.push_back(newEntry);

    if (newEntry.matched) {
        logger_.info("Log entry matched pattern {}: {}", newEntry.matchedPatternId, newEntry.message);
    }
}

void HIDSEngine::addPolicyViolation(const PolicyViolation& violation) {
    std::lock_guard<std::mutex> lock(mutex_);
    policyViolations_.push_back(violation);
}

} // namespace ThreatOne::HIDS
