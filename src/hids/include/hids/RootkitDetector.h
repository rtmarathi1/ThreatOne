#pragma once

#include "hids/IHIDSEngine.h"
#include "core/Logger.h"

#include <mutex>
#include <string>
#include <vector>
#include <map>
#include <cstdint>

namespace ThreatOne::HIDS {

enum class ScanDepth {
    Quick,
    Standard,
    Deep
};

struct RootkitScanResult {
    std::string scanId;
    ScanDepth depth = ScanDepth::Standard;
    bool clean = true;
    uint64_t processesScanned = 0;
    uint64_t filesScanned = 0;
    uint64_t modulesChecked = 0;
    uint64_t syscallsVerified = 0;
    std::vector<RootkitIndicator> indicators;
    std::string startedAt;
    std::string completedAt;
};

struct KnownRootkitSignature {
    std::string id;
    std::string name;
    RootkitType type = RootkitType::HiddenProcess;
    std::string signature;
    std::string description;
};

class RootkitDetector {
public:
    RootkitDetector();
    ~RootkitDetector() = default;

    // Scanning
    bool runScan(ScanDepth depth = ScanDepth::Standard);
    [[nodiscard]] RootkitScanResult getLastScanResult() const;
    [[nodiscard]] std::vector<RootkitIndicator> getIndicators() const;
    [[nodiscard]] bool isScanning() const;

    // Signature management
    std::string addSignature(const KnownRootkitSignature& sig);
    bool removeSignature(const std::string& sigId);
    [[nodiscard]] std::vector<KnownRootkitSignature> getSignatures() const;

    // Detection checks
    std::vector<RootkitIndicator> checkHiddenProcesses();
    std::vector<RootkitIndicator> checkHiddenFiles();
    std::vector<RootkitIndicator> checkKernelModules();
    std::vector<RootkitIndicator> checkSyscallHooks();

    // Stats
    [[nodiscard]] uint64_t getTotalScansPerformed() const;
    [[nodiscard]] uint64_t getTotalThreatsFound() const;

private:
    std::string generateIndicatorId();
    std::string generateScanId();
    std::string generateSignatureId();
    std::string getCurrentTimestamp() const;

    mutable std::mutex mutex_;

    bool scanning_ = false;
    RootkitScanResult lastResult_;
    std::vector<RootkitIndicator> indicators_;
    std::map<std::string, KnownRootkitSignature> signatures_;

    uint64_t totalScans_ = 0;
    uint64_t totalThreats_ = 0;

    int nextIndicatorId_ = 1;
    int nextScanId_ = 1;
    int nextSignatureId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::HIDS
