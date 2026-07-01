#pragma once

// ThreatOne Sandbox - Sandbox Engine Interface
// File detonation, behavior recording, verdict generation, sandbox profiles

#include <string>
#include <vector>
#include <optional>

namespace ThreatOne::Sandbox {

struct AnalysisResult {
    std::string id;
    std::string sampleHash;
    std::string verdict;
    double score = 0.0;
    std::vector<std::string> behaviors;
    std::string timestamp;
};

struct IOCInfo {
    std::string type;
    std::string value;
    std::string description;
    std::string confidence;
};

struct BehaviorReport {
    std::string sampleId;
    std::vector<std::string> processesCreated;
    std::vector<std::string> filesModified;
    std::vector<std::string> registryChanges;
    std::vector<std::string> networkConnections;
    std::vector<std::string> droppedFiles;
};

enum class ProfileType {
    Quick,
    Deep,
    Custom
};

struct SandboxProfile {
    std::string id;
    std::string name;
    ProfileType type = ProfileType::Quick;
    int timeoutSeconds = 60;
    bool networkSimulation = false;
    bool recordRegistry = true;
    bool recordFilesystem = true;
    bool recordNetwork = true;
};

enum class DetonationPriority {
    Low,
    Normal,
    High
};

struct DetonationConfig {
    std::string samplePath;
    std::string profileId;
    DetonationPriority priority = DetonationPriority::Normal;
};

enum class DetonationStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Timeout
};

struct DetonationJob {
    std::string id;
    DetonationConfig config;
    DetonationStatus status = DetonationStatus::Queued;
    std::string submittedAt;
    std::string startedAt;
    std::string completedAt;
    std::optional<AnalysisResult> result;
};

struct NetworkActivity {
    std::string protocol;
    std::string destination;
    int port = 0;
    std::string data;
    std::string timestamp;
};

enum class SandboxVerdict {
    Clean,
    Suspicious,
    Malicious,
    Unknown
};

class ISandboxEngine {
public:
    virtual ~ISandboxEngine() = default;

    // Original methods
    virtual std::string submitSample(const std::string& filePath) = 0;
    virtual AnalysisResult getAnalysis(const std::string& sampleId) = 0;
    virtual std::vector<IOCInfo> getIOCs(const std::string& sampleId) = 0;
    virtual BehaviorReport getBehaviorReport(const std::string& sampleId) = 0;
    virtual std::string detonateURL(const std::string& url) = 0;

    // Detonation with profile
    virtual std::string submitWithProfile(const DetonationConfig& config) = 0;
    [[nodiscard]] virtual std::optional<DetonationStatus> getDetonationStatus(const std::string& jobId) = 0;
    virtual bool cancelDetonation(const std::string& jobId) = 0;

    // Profile management
    virtual std::string createProfile(const SandboxProfile& profile) = 0;
    [[nodiscard]] virtual std::vector<SandboxProfile> getProfiles() = 0;
    [[nodiscard]] virtual std::optional<SandboxProfile> getProfile(const std::string& profileId) = 0;
    virtual bool deleteProfile(const std::string& profileId) = 0;

    // Network activity and verdict
    [[nodiscard]] virtual std::vector<NetworkActivity> getNetworkActivity(const std::string& sampleId) = 0;
    [[nodiscard]] virtual SandboxVerdict getVerdict(const std::string& sampleId) = 0;
};

} // namespace ThreatOne::Sandbox
