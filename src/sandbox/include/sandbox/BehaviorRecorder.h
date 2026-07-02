#pragma once

#include "sandbox/ISandboxEngine.h"
#include "core/Logger.h"

#include <mutex>
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace ThreatOne::Sandbox {

enum class BehaviorType {
    FileOperation,
    RegistryChange,
    ProcessCreation,
    NetworkConnection,
    FileDrop,
    SystemCall,
    MemoryOperation
};

struct BehaviorEntry {
    std::string id;
    std::string sampleId;
    BehaviorType type = BehaviorType::FileOperation;
    std::string action;
    std::string target;
    std::string details;
    std::string timestamp;
    int severity = 0;  // 0-10
};

struct RecordingSession {
    std::string id;
    std::string sampleId;
    bool active = false;
    std::string startedAt;
    std::string stoppedAt;
    uint64_t totalBehaviors = 0;
    bool recordFileOps = true;
    bool recordRegistry = true;
    bool recordProcesses = true;
    bool recordNetwork = true;
};

class BehaviorRecorder {
public:
    BehaviorRecorder();
    ~BehaviorRecorder() = default;

    // Session management
    std::string startRecording(const std::string& sampleId, bool fileOps = true,
                               bool registry = true, bool processes = true, bool network = true);
    bool stopRecording(const std::string& sessionId);
    [[nodiscard]] std::optional<RecordingSession> getSession(const std::string& sessionId) const;
    [[nodiscard]] std::vector<RecordingSession> getActiveSessions() const;

    // Record behaviors
    std::string recordFileOperation(const std::string& sampleId, const std::string& action,
                                    const std::string& path);
    std::string recordRegistryChange(const std::string& sampleId, const std::string& action,
                                     const std::string& key);
    std::string recordProcessCreation(const std::string& sampleId, const std::string& processName,
                                      const std::string& commandLine);
    std::string recordNetworkConnection(const std::string& sampleId, const std::string& destination,
                                        int port);
    std::string recordFileDrop(const std::string& sampleId, const std::string& path,
                               const std::string& hash);

    // Query behaviors
    [[nodiscard]] std::vector<BehaviorEntry> getBehaviors(const std::string& sampleId) const;
    [[nodiscard]] std::vector<BehaviorEntry> getBehaviorsByType(const std::string& sampleId,
                                                                BehaviorType type) const;
    [[nodiscard]] uint64_t getBehaviorCount(const std::string& sampleId) const;

    // Convert to BehaviorReport
    [[nodiscard]] BehaviorReport generateBehaviorReport(const std::string& sampleId) const;

    // Statistics
    [[nodiscard]] uint64_t getTotalRecordedBehaviors() const;
    [[nodiscard]] uint64_t getActiveSessionCount() const;

private:
    std::string generateId(const std::string& prefix);
    std::string getCurrentTimestamp() const;
    bool isRecordingEnabled(const std::string& sampleId, BehaviorType type) const;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, RecordingSession> sessions_; // sessionId -> session
    std::unordered_map<std::string, std::string> sampleToSession_; // sampleId -> sessionId
    std::unordered_map<std::string, std::vector<BehaviorEntry>> behaviors_; // sampleId -> entries
    int nextSessionId_ = 1;
    int nextBehaviorId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Sandbox
