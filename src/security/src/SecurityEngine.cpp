#include "security/SecurityEngine.h"
#include <mutex>
#include "threat_intel/ThreatIntelEngine.h"
#include "scanner/ScanEngine.h"
#include "scanner/QuarantineManager.h"
#include "edr/ProcessMonitor.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace ThreatOne::Security {

SecurityEngine::SecurityEngine()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("SecurityEngine")) {
    // Initialize threat intelligence engine
    threatIntelEngine_ = std::make_unique<ThreatOne::ThreatIntel::ThreatIntelEngine>();
    threatIntelEngine_->initialize();

    // Initialize scanner engine
    scanEngine_ = std::make_shared<ThreatOne::Scanner::ScanEngine>();

    // Initialize EDR process monitor
    processMonitor_ = std::make_shared<ThreatOne::EDR::ProcessMonitor>();

    logger_.info("SecurityEngine initialized with Scanner, EDR, and ThreatIntel integration");
}

SecurityEngine::~SecurityEngine() = default;

std::string SecurityEngine::generateThreatId() {
    return "THREAT-" + std::to_string(nextThreatId_++);
}

void SecurityEngine::addThreat(const ThreatInfo& threat) {
    std::lock_guard<std::mutex> lock(threatsMutex_);
    threatIndex_[threat.id] = detectedThreats_.size();
    detectedThreats_.push_back(threat);
}

bool SecurityEngine::scanFile(const std::string& filePath) {
    logger_.info("Scanning file: {}", filePath);

    // Delegate to the Scanner module's ScanEngine
    Scanner::ScanConfig config;
    config.type = Scanner::ScanType::Custom;
    config.targets.push_back(filePath);

    std::string scanId = scanEngine_->startScan(config);
    if (scanId.empty()) {
        logger_.error("Failed to start scan for file: {}", filePath);
        return false;
    }

    // Get scan result
    auto result = scanEngine_->getScanStatus(scanId);

    // If threats were found, track them
    if (result.threatsFound > 0) {
        for (const auto& finding : result.findings) {
            ThreatInfo threat;
            threat.id = generateThreatId();
            threat.name = finding;
            threat.description = "Threat detected in file scan";
            threat.filePath = filePath;
            threat.severity = ThreatSeverity::High;
            threat.detectedBy = DetectionType::Signature;
            threat.quarantined = false;
            addThreat(threat);
        }
        logger_.warn("File scan detected {} threat(s) in: {}", result.threatsFound, filePath);
        return false; // File is infected
    }

    // Also check threat intelligence for the file path
    if (checkThreatIntel(filePath)) {
        ThreatInfo threat;
        threat.id = generateThreatId();
        threat.name = "ThreatIntel Match";
        threat.description = "File matched threat intelligence indicator";
        threat.filePath = filePath;
        threat.severity = ThreatSeverity::Medium;
        threat.detectedBy = DetectionType::Heuristic;
        threat.quarantined = false;
        addThreat(threat);
        logger_.warn("Threat intelligence match for file: {}", filePath);
        return false; // Suspicious file
    }

    logger_.info("File scan clean: {}", filePath);
    return true; // File is clean
}

bool SecurityEngine::scanMemory(uint64_t processId) {
    logger_.info("Scanning memory for PID: {}", processId);

    // Use EDR ProcessMonitor to get process information
    auto processes = processMonitor_->enumerateProcesses();

    // Find the target process
    auto it = std::find_if(processes.begin(), processes.end(),
        [processId](const EDR::ProcessInfo& p) { return p.pid == processId; });

    if (it == processes.end()) {
        logger_.warn("Process {} not found during memory scan", processId);
        return false;
    }

    const auto& procInfo = *it;
    logger_.info("Scanning process: {} (PID: {}, path: {})",
                 procInfo.name, procInfo.pid, procInfo.path);

    // Analyze command line for suspicious patterns
    auto cmdAnalysis = processMonitor_->analyzeCommandLine(procInfo.commandLine);
    if (cmdAnalysis.score > 0.7) {
        ThreatInfo threat;
        threat.id = generateThreatId();
        threat.name = "Suspicious Process Behavior";
        threat.description = "Process command line analysis indicates suspicious activity (score: " +
                           std::to_string(cmdAnalysis.score) + ")";
        threat.filePath = procInfo.path;
        threat.severity = (cmdAnalysis.score > 0.9) ? ThreatSeverity::Critical : ThreatSeverity::High;
        threat.detectedBy = DetectionType::Behavior;
        threat.quarantined = false;
        addThreat(threat);
        logger_.warn("Suspicious process detected: {} (score: {:.2f})", procInfo.name, cmdAnalysis.score);
        return false; // Suspicious process
    }

    // Check for suspicious process tree
    auto treeIndicators = processMonitor_->detectSuspiciousProcessTree(processId);
    if (!treeIndicators.empty()) {
        for (const auto& indicator : treeIndicators) {
            if (indicator.severity > 0.5) {
                ThreatInfo threat;
                threat.id = generateThreatId();
                threat.name = "Suspicious Process Tree: " + indicator.type;
                threat.description = indicator.description;
                threat.filePath = procInfo.path;
                threat.severity = (indicator.severity > 0.8) ? ThreatSeverity::High : ThreatSeverity::Medium;
                threat.detectedBy = DetectionType::Behavior;
                threat.quarantined = false;
                addThreat(threat);
            }
        }
        logger_.warn("Suspicious process tree detected for PID: {}", processId);
        return false;
    }

    // Also check threat intelligence for the process path
    if (!procInfo.path.empty() && checkThreatIntel(procInfo.path)) {
        ThreatInfo threat;
        threat.id = generateThreatId();
        threat.name = "ThreatIntel Process Match";
        threat.description = "Process executable matched threat intelligence indicator";
        threat.filePath = procInfo.path;
        threat.severity = ThreatSeverity::High;
        threat.detectedBy = DetectionType::Heuristic;
        threat.quarantined = false;
        addThreat(threat);
        return false;
    }

    logger_.info("Memory scan clean for PID: {}", processId);
    return true; // Process is clean
}

bool SecurityEngine::quarantine(const std::string& threatId) {
    logger_.info("Quarantining threat: {}", threatId);

    // Find the threat in our tracked list
    std::lock_guard<std::mutex> lock(threatsMutex_);
    auto indexIt = threatIndex_.find(threatId);
    if (indexIt == threatIndex_.end()) {
        logger_.error("Threat not found for quarantine: {}", threatId);
        return false;
    }

    auto& threat = detectedThreats_[indexIt->second];
    if (threat.quarantined) {
        logger_.info("Threat already quarantined: {}", threatId);
        return true;
    }

    if (threat.filePath.empty()) {
        logger_.error("No file path associated with threat: {}", threatId);
        return false;
    }

    // Delegate to QuarantineManager from Scanner module
    auto& quarantineMgr = scanEngine_->quarantineManager();
    auto result = quarantineMgr.quarantine(
        std::filesystem::path(threat.filePath),
        "Quarantined by SecurityEngine: " + threat.name);

    if (result.isOk()) {
        threat.quarantined = true;
        logger_.info("Successfully quarantined file: {} (threat: {})", threat.filePath, threatId);
        return true;
    }

    logger_.error("Failed to quarantine file {}: {}", threat.filePath, result.error().message());
    return false;
}

std::vector<ThreatInfo> SecurityEngine::getThreats() {
    std::lock_guard<std::mutex> lock(threatsMutex_);
    return detectedThreats_;
}

ThreatInfo SecurityEngine::getThreatById(const std::string& id) {
    std::lock_guard<std::mutex> lock(threatsMutex_);
    auto indexIt = threatIndex_.find(id);
    if (indexIt != threatIndex_.end()) {
        return detectedThreats_[indexIt->second];
    }

    logger_.warn("Threat not found: {}", id);
    return ThreatInfo{id, "Not Found", "No threat with this ID exists", "",
                      ThreatSeverity::Low, DetectionType::Signature, false};
}

std::vector<DetectionEngineInfo> SecurityEngine::getDetectionEngines() {
    logger_.info("Retrieving detection engine information");

    std::vector<DetectionEngineInfo> engines;

    // Signature engine (powered by Scanner's SignatureDatabase)
    engines.push_back({"Signature Engine", "2.0.0", DetectionType::Signature, true});

    // Behavior engine (powered by EDR ProcessMonitor)
    engines.push_back({"Behavior Engine", "2.0.0", DetectionType::Behavior, true});

    // Heuristic engine (powered by ThreatIntel)
    engines.push_back({"Heuristic Engine", "2.0.0", DetectionType::Heuristic, true});

    // YARA engine (powered by Scanner's YaraEngine)
    engines.push_back({"YARA Engine", "2.0.0", DetectionType::Heuristic, true});

    // Memory scanning (powered by EDR)
    engines.push_back({"Memory Scanner", "2.0.0", DetectionType::Memory, true});

    return engines;
}

bool SecurityEngine::checkThreatIntel(const std::string& indicator) {
    if (!threatIntelEngine_) {
        logger_.error("ThreatIntelEngine not available");
        return false;
    }

    auto result = threatIntelEngine_->processIndicator(indicator);
    if (result.matched) {
        logger_.info("Threat intel match for '{}': score={:.1f}, matches={}",
                     indicator, result.score.overallScore, result.matches.size());
    }
    return result.matched;
}

} // namespace ThreatOne::Security
