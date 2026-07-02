#pragma once

// ThreatOne Sandbox - Sandbox Engine Implementation
// File detonation, behavior recording, verdict generation, profiles

#include "sandbox/ISandboxEngine.h"
#include "sandbox/ProcessSandbox.h"
#include "sandbox/NetworkSandbox.h"
#include "sandbox/BehaviorRecorder.h"
#include "sandbox/SandboxAnalyzer.h"
#include "sandbox/MalwareDetonation.h"
#include "sandbox/SandboxReporter.h"
#include "core/Logger.h"

#include <mutex>
#include <memory>
#include <unordered_map>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace ThreatOne::Sandbox {

class SandboxEngine : public ISandboxEngine {
public:
    SandboxEngine();
    ~SandboxEngine() override = default;

    // Original methods
    std::string submitSample(const std::string& filePath) override;
    AnalysisResult getAnalysis(const std::string& sampleId) override;
    std::vector<IOCInfo> getIOCs(const std::string& sampleId) override;
    BehaviorReport getBehaviorReport(const std::string& sampleId) override;
    std::string detonateURL(const std::string& url) override;

    // Detonation with profile
    std::string submitWithProfile(const DetonationConfig& config) override;
    [[nodiscard]] std::optional<DetonationStatus> getDetonationStatus(const std::string& jobId) override;
    bool cancelDetonation(const std::string& jobId) override;

    // Profile management
    std::string createProfile(const SandboxProfile& profile) override;
    [[nodiscard]] std::vector<SandboxProfile> getProfiles() override;
    [[nodiscard]] std::optional<SandboxProfile> getProfile(const std::string& profileId) override;
    bool deleteProfile(const std::string& profileId) override;

    // Network activity and verdict
    [[nodiscard]] std::vector<NetworkActivity> getNetworkActivity(const std::string& sampleId) override;
    [[nodiscard]] SandboxVerdict getVerdict(const std::string& sampleId) override;

    // Non-interface helpers for testing
    void addBehavior(const std::string& sampleId, const std::string& behavior);
    void addNetworkActivity(const std::string& sampleId, const NetworkActivity& activity);
    void completeDetonation(const std::string& jobId);

    // Access to sub-components
    [[nodiscard]] ProcessSandbox& getProcessSandbox() { return *processSandbox_; }
    [[nodiscard]] NetworkSandbox& getNetworkSandbox() { return *networkSandbox_; }
    [[nodiscard]] BehaviorRecorder& getBehaviorRecorder() { return *behaviorRecorder_; }
    [[nodiscard]] SandboxAnalyzer& getSandboxAnalyzer() { return *sandboxAnalyzer_; }
    [[nodiscard]] MalwareDetonation& getMalwareDetonation() { return *malwareDetonation_; }
    [[nodiscard]] SandboxReporter& getSandboxReporter() { return *sandboxReporter_; }

private:
    std::string generateSampleId();
    std::string generateJobId();
    std::string generateProfileId();
    std::string getCurrentTimestamp() const;
    SandboxVerdict computeVerdict(const std::vector<std::string>& behaviors) const;
    std::vector<IOCInfo> extractIOCs(const BehaviorReport& report) const;
    void initDefaultProfiles();

    mutable std::mutex mutex_;
    std::unordered_map<std::string, BehaviorReport> reports_;
    std::unordered_map<std::string, DetonationJob> jobs_;
    std::map<std::string, SandboxProfile> profiles_;
    std::unordered_map<std::string, std::vector<NetworkActivity>> networkActivities_;
    std::unordered_map<std::string, std::string> sampleToJob_;  // sampleId -> jobId
    int nextSampleId_ = 1;
    int nextJobId_ = 1;
    int nextProfileId_ = 1;

    // Sub-components
    std::shared_ptr<ProcessSandbox> processSandbox_;
    std::shared_ptr<NetworkSandbox> networkSandbox_;
    std::shared_ptr<BehaviorRecorder> behaviorRecorder_;
    std::shared_ptr<SandboxAnalyzer> sandboxAnalyzer_;
    std::shared_ptr<MalwareDetonation> malwareDetonation_;
    std::shared_ptr<SandboxReporter> sandboxReporter_;

    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Sandbox
