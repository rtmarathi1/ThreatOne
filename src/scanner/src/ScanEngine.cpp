#include "scanner/ScanEngine.h"

#include <utils/CryptoUtils.h>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace ThreatOne::Scanner {

ScanEngine::ScanEngine()
    : ScanEngine(std::filesystem::temp_directory_path() / "threatone_quarantine") {
}

ScanEngine::ScanEngine(const std::filesystem::path& quarantineDir)
    : logger_(Core::Logger::instance().getModuleLogger("ScanEngine"))
    , matcher_(sigDb_)
    , scheduler_(2)  // Default 2 worker threads for scanning
    , quarantineManager_(quarantineDir) {

    // Initialize sub-components
    quarantineManager_.initialize();
    yaraEngine_.initialize();
    scheduler_.start();

    logger_.info("ScanEngine initialized (quarantine: {})", quarantineDir.string());
}

ScanEngine::~ScanEngine() {
    scheduler_.stop();
}

std::string ScanEngine::startScan(const ScanConfig& config) {
    std::string scanId = Utils::CryptoUtils::generateUUID();

    auto scan = std::make_shared<ActiveScan>();
    scan->scanId = scanId;
    scan->config = config;
    scan->status = ScanStatus::Running;
    scan->progress = std::make_unique<ScanProgress>();

    // Determine target paths based on scan type
    auto targets = getTargetsForType(config);

    // Enumerate files
    EnumerationConfig enumConfig;
    enumConfig.targets = targets;
    enumConfig.exclusionPatterns = config.exclusions;
    enumConfig.followSymlinks = false;

    auto enumResult = enumerator_.enumerate(enumConfig);
    if (enumResult.isErr()) {
        logger_.error("Failed to enumerate files: {}", enumResult.error().message());
        scan->status = ScanStatus::Failed;
        {
            std::lock_guard<std::mutex> lock(scansMutex_);
            activeScans_[scanId] = scan;
        }
        return scanId;
    }

    auto& files = enumResult.value();
    scan->progress->reset(static_cast<uint64_t>(files.size()));

    logger_.info("Scan {} started: type={}, files={}", scanId,
                 static_cast<int>(config.type), files.size());

    // Register the scan
    {
        std::lock_guard<std::mutex> lock(scansMutex_);
        activeScans_[scanId] = scan;
    }

    // Publish scan started event
    Core::SecurityEvent startEvent(
        Core::SecurityEvent::Type::ScanStarted,
        Core::SecurityEvent::Severity::Info,
        "Scan started: " + scanId);
    Core::EventBus::instance().publish(startEvent);

    // Process files (for simplicity, process inline on current thread for small scans,
    // or use scheduler for larger scans)
    if (files.size() <= 100) {
        // Small scan - process directly
        for (const auto& file : files) {
            if (scan->status == ScanStatus::Cancelled) break;
            if (scan->status == ScanStatus::Paused) break;
            processFile(file, *scan);
        }
        if (scan->status == ScanStatus::Running) {
            scan->status = ScanStatus::Completed;
        }
    } else {
        // Larger scan - use scheduler
        auto scanPtr = scan;
        scheduler_.submitBatch(files,
            [this, scanPtr](const std::filesystem::path& file) {
                if (scanPtr->status == ScanStatus::Cancelled) return;
                if (scanPtr->status == ScanStatus::Paused) return;
                processFile(file, *scanPtr);
            });

        // Wait for completion (simple polling)
        while (!scan->progress->isComplete() &&
               scan->status == ScanStatus::Running) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            if (scheduler_.pendingJobCount() == 0 &&
                scan->progress->filesScanned() >= scan->progress->totalFiles()) {
                break;
            }
        }
        if (scan->status == ScanStatus::Running) {
            scan->status = ScanStatus::Completed;
        }
    }

    // Publish scan completed event
    Core::SecurityEvent endEvent(
        Core::SecurityEvent::Type::ScanCompleted,
        Core::SecurityEvent::Severity::Info,
        "Scan completed: " + scanId + " threats=" +
        std::to_string(scan->progress->threatsFound()));
    Core::EventBus::instance().publish(endEvent);

    logger_.info("Scan {} completed: {} files, {} threats",
                 scanId, scan->progress->filesScanned(), scan->progress->threatsFound());

    return scanId;
}

bool ScanEngine::stopScan(const std::string& scanId) {
    std::lock_guard<std::mutex> lock(scansMutex_);
    auto it = activeScans_.find(scanId);
    if (it == activeScans_.end()) return false;

    it->second->status = ScanStatus::Cancelled;
    scheduler_.cancelPending();
    logger_.info("Scan {} cancelled", scanId);
    return true;
}

bool ScanEngine::pauseScan(const std::string& scanId) {
    std::lock_guard<std::mutex> lock(scansMutex_);
    auto it = activeScans_.find(scanId);
    if (it == activeScans_.end()) return false;

    if (it->second->status == ScanStatus::Running) {
        it->second->status = ScanStatus::Paused;
        logger_.info("Scan {} paused", scanId);
        return true;
    }
    return false;
}

ScanResult ScanEngine::getScanStatus(const std::string& scanId) {
    std::shared_ptr<ActiveScan> scan;
    {
        std::lock_guard<std::mutex> lock(scansMutex_);
        auto it = activeScans_.find(scanId);
        if (it == activeScans_.end()) {
            return {scanId, ScanStatus::Idle, 0, 0, 0.0, {}};
        }
        scan = it->second;
    }

    ScanResult result;
    result.scanId = scanId;
    result.status = scan->status;
    result.filesScanned = scan->progress->filesScanned();
    result.threatsFound = scan->progress->threatsFound();
    result.progress = scan->progress->percentage();
    {
        std::lock_guard<std::mutex> lock(scan->findingsMutex);
        result.findings = scan->findings;
    }
    return result;
}

std::vector<ScanResult> ScanEngine::getScanResults() {
    std::lock_guard<std::mutex> lock(scansMutex_);
    std::vector<ScanResult> results;
    results.reserve(activeScans_.size());

    for (const auto& [id, scan] : activeScans_) {
        ScanResult result;
        result.scanId = id;
        result.status = scan->status;
        result.filesScanned = scan->progress->filesScanned();
        result.threatsFound = scan->progress->threatsFound();
        result.progress = scan->progress->percentage();
        {
            std::lock_guard<std::mutex> findingsLock(scan->findingsMutex);
            result.findings = scan->findings;
        }
        results.push_back(std::move(result));
    }

    return results;
}

Core::Result<size_t, Core::Error> ScanEngine::loadSignatures(const std::filesystem::path& path) {
    return sigDb_.loadFromJson(path);
}

Core::Result<size_t, Core::Error> ScanEngine::loadSignaturesFromString(const std::string& json) {
    return sigDb_.loadFromJsonString(json);
}

void ScanEngine::setQuickScanPaths(const std::vector<std::filesystem::path>& paths) {
    defaultQuickScanPaths_ = paths;
}

void ScanEngine::setFullScanPaths(const std::vector<std::filesystem::path>& paths) {
    defaultFullScanPaths_ = paths;
}

std::vector<std::filesystem::path> ScanEngine::getTargetsForType(const ScanConfig& config) const {
    std::vector<std::filesystem::path> targets;

    switch (config.type) {
        case ScanType::Quick:
            // Quick scan: use configured paths, falling back to platform defaults
            if (!defaultQuickScanPaths_.empty()) {
                targets = defaultQuickScanPaths_;
            } else {
                #ifdef _WIN32
                targets = {"C:\\Windows\\System32", "C:\\Program Files"};
                #else
                targets = {"/usr/bin", "/usr/sbin"};
                #endif
            }
            break;

        case ScanType::Full:
            // Full scan: use provided targets, then configured defaults, then platform default
            if (!config.targets.empty()) {
                for (const auto& t : config.targets) {
                    targets.emplace_back(t);
                }
            } else if (!defaultFullScanPaths_.empty()) {
                targets = defaultFullScanPaths_;
            } else {
                #ifdef _WIN32
                targets = {"C:\\"};
                #else
                targets = {"/"};
                #endif
            }
            break;

        case ScanType::Custom:
            // Custom scan: user-specified paths
            for (const auto& t : config.targets) {
                targets.emplace_back(t);
            }
            break;

        case ScanType::Memory:
            // Memory scan: scan /proc for suspicious memory-mapped regions
            targets = {"/proc"};
            break;

        case ScanType::IOC:
            // IOC scan: indicator matching on specified paths
            for (const auto& t : config.targets) {
                targets.emplace_back(t);
            }
            break;

        default:
            // For other scan types, use provided targets
            for (const auto& t : config.targets) {
                targets.emplace_back(t);
            }
            break;
    }

    return targets;
}

void ScanEngine::processFile(const std::filesystem::path& file, ActiveScan& scan) {
    scan.progress->setCurrentFile(file.string());

    // Get file size for byte tracking
    std::error_code ec;
    auto fileSize = std::filesystem::file_size(file, ec);
    if (!ec) {
        scan.progress->addBytes(fileSize);
    }

    // Match against signature database
    auto matchResult = matcher_.matchFile(file);
    if (matchResult.isOk() && matchResult.value().matched) {
        auto& match = matchResult.value();
        scan.progress->incrementThreats();

        std::string finding = file.string() + " [" +
            match.signature->name + " - " +
            threatLevelToString(match.signature->threatLevel) + "]";
        {
            std::lock_guard<std::mutex> lock(scan.findingsMutex);
            scan.findings.push_back(finding);
        }

        // Publish threat detection event
        publishThreatEvent(file.string(), *match.signature);

        logger_.warn("Threat detected: {} in {}", match.signature->name, file.string());
    }

    // Match against YARA rules (if any are loaded and compiled)
    if (yaraEngine_.status() == YaraEngineStatus::Ready && yaraEngine_.ruleCount() > 0) {
        auto yaraResult = yaraEngine_.matchFile(file);
        if (yaraResult.isOk() && !yaraResult.value().empty()) {
            for (const auto& yaraMatch : yaraResult.value()) {
                scan.progress->incrementThreats();

                std::string finding = file.string() + " [YARA:" +
                    yaraMatch.ruleName + "]";
                {
                    std::lock_guard<std::mutex> lock(scan.findingsMutex);
                    scan.findings.push_back(finding);
                }

                logger_.warn("YARA match: {} in {}", yaraMatch.ruleName, file.string());
            }
        }
    }

    scan.progress->incrementScanned();
}

void ScanEngine::publishThreatEvent(const std::string& filePath, const Signature& sig) {
    Core::SecurityEvent::Severity severity;
    switch (sig.threatLevel) {
        case ThreatLevel::Low:      severity = Core::SecurityEvent::Severity::Low; break;
        case ThreatLevel::Medium:   severity = Core::SecurityEvent::Severity::Medium; break;
        case ThreatLevel::High:     severity = Core::SecurityEvent::Severity::High; break;
        case ThreatLevel::Critical: severity = Core::SecurityEvent::Severity::Critical; break;
    }

    Core::SecurityEvent event(
        Core::SecurityEvent::Type::ThreatDetected,
        severity,
        "Threat detected: " + sig.name + " in " + filePath);
    event.setSource("ScanEngine");
    Core::EventBus::instance().publish(event);
}

} // namespace ThreatOne::Scanner
