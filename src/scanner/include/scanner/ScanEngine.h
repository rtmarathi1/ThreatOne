#pragma once

// ThreatOne Scanner - Scan Engine (Orchestrator)
// Coordinates all scanner components: FileHasher, SignatureDatabase,
// SignatureMatcher, YaraEngine, ScanScheduler, FileEnumerator,
// ScanProgress, QuarantineManager, ScanHistory.

#include "scanner/IScanEngine.h"
#include "scanner/FileHasher.h"
#include "scanner/SignatureDatabase.h"
#include "scanner/SignatureMatcher.h"
#include "scanner/YaraEngine.h"
#include "scanner/ScanScheduler.h"
#include "scanner/FileEnumerator.h"
#include "scanner/ScanProgress.h"
#include "scanner/QuarantineManager.h"

#include <core/Logger.h>
#include <core/EventBus.h>
#include <core/Event.h>

#include <unordered_map>
#include <mutex>
#include <filesystem>
#include <memory>

namespace ThreatOne::Scanner {

// Internal scan state
struct ActiveScan {
    std::string scanId;
    ScanConfig config;
    ScanStatus status = ScanStatus::Running;
    std::unique_ptr<ScanProgress> progress;
    std::vector<std::string> findings;
};

// Main scan engine orchestrator
class ScanEngine : public IScanEngine {
public:
    ScanEngine();
    explicit ScanEngine(const std::filesystem::path& quarantineDir);
    ~ScanEngine() override;

    // IScanEngine interface
    std::string startScan(const ScanConfig& config) override;
    bool stopScan(const std::string& scanId) override;
    bool pauseScan(const std::string& scanId) override;
    ScanResult getScanStatus(const std::string& scanId) override;
    std::vector<ScanResult> getScanResults() override;

    // Access to sub-components
    SignatureDatabase& signatureDatabase() { return sigDb_; }
    YaraEngine& yaraEngine() { return yaraEngine_; }
    QuarantineManager& quarantineManager() { return quarantineManager_; }

    // Load signature database from JSON
    Core::Result<size_t, Core::Error> loadSignatures(const std::filesystem::path& path);
    Core::Result<size_t, Core::Error> loadSignaturesFromString(const std::string& json);

private:
    // Get target paths based on scan type
    std::vector<std::filesystem::path> getTargetsForType(const ScanConfig& config) const;

    // Process a single file during scanning
    void processFile(const std::filesystem::path& file, ActiveScan& scan);

    // Publish a security event for a threat detection
    void publishThreatEvent(const std::string& filePath, const Signature& sig);

    Core::ModuleLogger logger_;
    SignatureDatabase sigDb_;
    SignatureMatcher matcher_;
    YaraEngine yaraEngine_;
    ScanScheduler scheduler_;
    FileEnumerator enumerator_;
    QuarantineManager quarantineManager_;

    mutable std::mutex scansMutex_;
    std::unordered_map<std::string, std::shared_ptr<ActiveScan>> activeScans_;
};

} // namespace ThreatOne::Scanner
