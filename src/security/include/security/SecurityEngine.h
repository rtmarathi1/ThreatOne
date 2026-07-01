#pragma once

#include "security/ISecurityEngine.h"
#include "core/Logger.h"

namespace ThreatOne::Security {

class SecurityEngine : public ISecurityEngine {
public:
    SecurityEngine();
    ~SecurityEngine() override = default;

    bool scanFile(const std::string& filePath) override;
    bool scanMemory(uint64_t processId) override;
    bool quarantine(const std::string& threatId) override;
    std::vector<ThreatInfo> getThreats() override;
    ThreatInfo getThreatById(const std::string& id) override;
    std::vector<DetectionEngineInfo> getDetectionEngines() override;

private:
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Security
