#pragma once

#include "security/ISecurityEngine.h"
#include "core/Logger.h"

#include <memory>
#include <string>
#include <cstdint>
#include <vector>
#include <mutex>
#include <atomic>
#include <unordered_map>

namespace ThreatOne::ThreatIntel {
    class ThreatIntelEngine;
}

namespace ThreatOne::Scanner {
    class ScanEngine;
}

namespace ThreatOne::EDR {
    class ProcessMonitor;
}

namespace ThreatOne::Security {

class SecurityEngine : public ISecurityEngine {
public:
    SecurityEngine();
    ~SecurityEngine() override;

    bool scanFile(const std::string& filePath) override;
    bool scanMemory(uint64_t processId) override;
    bool quarantine(const std::string& threatId) override;
    std::vector<ThreatInfo> getThreats() override;
    ThreatInfo getThreatById(const std::string& id) override;
    std::vector<DetectionEngineInfo> getDetectionEngines() override;

    // Threat Intelligence integration
    bool checkThreatIntel(const std::string& indicator);

private:
    // Generate a unique threat ID
    std::string generateThreatId();

    // Add a detected threat to internal tracking
    void addThreat(const ThreatInfo& threat);

    ThreatOne::Core::ModuleLogger logger_;
    std::unique_ptr<ThreatOne::ThreatIntel::ThreatIntelEngine> threatIntelEngine_;
    std::shared_ptr<ThreatOne::Scanner::ScanEngine> scanEngine_;
    std::shared_ptr<ThreatOne::EDR::ProcessMonitor> processMonitor_;

    // Thread-safe threat tracking
    mutable std::mutex threatsMutex_;
    std::vector<ThreatInfo> detectedThreats_;
    std::unordered_map<std::string, size_t> threatIndex_; // id -> index in detectedThreats_
    std::atomic<uint64_t> nextThreatId_{1};
};

} // namespace ThreatOne::Security
