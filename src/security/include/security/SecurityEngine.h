#pragma once

#include "security/ISecurityEngine.h"
#include "core/Logger.h"

#include <memory>
#include <string>

namespace ThreatOne::ThreatIntel {
    class ThreatIntelEngine;
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
    ThreatOne::Core::ModuleLogger logger_;
    std::unique_ptr<ThreatOne::ThreatIntel::ThreatIntelEngine> threatIntelEngine_;
};

} // namespace ThreatOne::Security
