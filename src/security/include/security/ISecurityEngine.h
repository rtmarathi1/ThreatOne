#pragma once

#include <string>
#include <vector>
#include <memory>
#include <cstdint>

namespace ThreatOne::Security {

enum class DetectionType {
    Signature,
    Behavior,
    Heuristic,
    ML,
    AI,
    Memory,
    Sandbox,
    Cloud
};

enum class ThreatSeverity {
    Low,
    Medium,
    High,
    Critical
};

struct ThreatInfo {
    std::string id;
    std::string name;
    std::string description;
    std::string filePath;
    ThreatSeverity severity = ThreatSeverity::Low;
    DetectionType detectedBy = DetectionType::Signature;
    bool quarantined = false;
};

struct DetectionEngineInfo {
    std::string name;
    std::string version;
    DetectionType type;
    bool enabled = true;
};

class ISecurityEngine {
public:
    virtual ~ISecurityEngine() = default;

    virtual bool scanFile(const std::string& filePath) = 0;
    virtual bool scanMemory(uint64_t processId) = 0;
    virtual bool quarantine(const std::string& threatId) = 0;
    virtual std::vector<ThreatInfo> getThreats() = 0;
    virtual ThreatInfo getThreatById(const std::string& id) = 0;
    virtual std::vector<DetectionEngineInfo> getDetectionEngines() = 0;
};

} // namespace ThreatOne::Security
