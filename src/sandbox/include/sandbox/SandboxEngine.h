#pragma once

#include "sandbox/ISandboxEngine.h"
#include "core/Logger.h"

namespace ThreatOne::Sandbox {

class SandboxEngine : public ISandboxEngine {
public:
    SandboxEngine();
    ~SandboxEngine() override = default;

    std::string submitSample(const std::string& filePath) override;
    AnalysisResult getAnalysis(const std::string& sampleId) override;
    std::vector<IOCInfo> getIOCs(const std::string& sampleId) override;
    BehaviorReport getBehaviorReport(const std::string& sampleId) override;
    std::string detonateURL(const std::string& url) override;

private:
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Sandbox
