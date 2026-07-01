#include "sandbox/SandboxEngine.h"

namespace ThreatOne::Sandbox {

SandboxEngine::SandboxEngine()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("SandboxEngine")) {
    logger_.info("SandboxEngine initialized (stub)");
}

std::string SandboxEngine::submitSample(const std::string& filePath) {
    logger_.info("submitSample called: {}", filePath);
    return "SAMPLE-001";
}

AnalysisResult SandboxEngine::getAnalysis(const std::string& sampleId) {
    logger_.info("getAnalysis called: {}", sampleId);
    return {sampleId, "", "clean", 0.0, {}, ""};
}

std::vector<IOCInfo> SandboxEngine::getIOCs(const std::string& sampleId) {
    logger_.info("getIOCs called: {}", sampleId);
    return {};
}

BehaviorReport SandboxEngine::getBehaviorReport(const std::string& sampleId) {
    logger_.info("getBehaviorReport called: {}", sampleId);
    return {sampleId, {}, {}, {}, {}, {}};
}

std::string SandboxEngine::detonateURL(const std::string& url) {
    logger_.info("detonateURL called: {}", url);
    return "URL-ANALYSIS-001";
}

} // namespace ThreatOne::Sandbox
