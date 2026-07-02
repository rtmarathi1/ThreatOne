#include "security/SecurityEngine.h"
#include "threat_intel/ThreatIntelEngine.h"
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ThreatOne::Security {

SecurityEngine::SecurityEngine()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("SecurityEngine")) {
    // Initialize threat intelligence engine
    threatIntelEngine_ = std::make_unique<ThreatOne::ThreatIntel::ThreatIntelEngine>();
    threatIntelEngine_->initialize();
    logger_.info("SecurityEngine initialized with ThreatIntel integration");
}

SecurityEngine::~SecurityEngine() = default;

bool SecurityEngine::scanFile(const std::string& filePath) {
    logger_.info("scanFile called: {}", filePath);
    return true;
}

bool SecurityEngine::scanMemory(uint64_t processId) {
    logger_.info("scanMemory called: PID {}", processId);
    return true;
}

bool SecurityEngine::quarantine(const std::string& threatId) {
    logger_.info("quarantine called: {}", threatId);
    return true;
}

std::vector<ThreatInfo> SecurityEngine::getThreats() {
    logger_.info("getThreats called");
    return {};
}

ThreatInfo SecurityEngine::getThreatById(const std::string& id) {
    logger_.info("getThreatById called: {}", id);
    return ThreatInfo{id, "Unknown", "Stub threat", "", ThreatSeverity::Low, DetectionType::Signature, false};
}

std::vector<DetectionEngineInfo> SecurityEngine::getDetectionEngines() {
    logger_.info("getDetectionEngines called");
    return {
        {"Signature Engine", "1.0.0", DetectionType::Signature, true},
        {"Behavior Engine", "1.0.0", DetectionType::Behavior, true},
        {"Heuristic Engine", "1.0.0", DetectionType::Heuristic, true},
        {"ML Engine", "1.0.0", DetectionType::ML, true}
    };
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
