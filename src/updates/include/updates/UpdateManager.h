#pragma once

// ThreatOne Updates - Update Manager Implementation
// Full update lifecycle, channels, staged rollouts, signature updates

#include "updates/IUpdateManager.h"
#include "core/Logger.h"

#include <mutex>
#include <unordered_map>
#include <vector>
#include <optional>
#include <string>

namespace ThreatOne::Updates {

class UpdateManager : public IUpdateManager {
public:
    UpdateManager();
    ~UpdateManager() override = default;

    // Core update operations
    std::vector<UpdateInfo> checkForUpdates() override;
    bool downloadUpdate(const std::string& version) override;
    bool installUpdate(const std::string& version) override;
    VersionInfo getVersion() override;
    bool rollback() override;
    bool cancelUpdate(const std::string& version) override;

    // Channel management
    void setUpdateChannel(UpdateChannel channel) override;
    [[nodiscard]] UpdateChannel getUpdateChannel() const override;

    // Progress tracking
    std::optional<UpdateProgress> getUpdateProgress(const std::string& version) override;

    // Staged rollouts
    std::optional<StagedRollout> stageRollout(const std::string& version, int percentage) override;

    // Signature updates
    std::vector<SignatureUpdate> getSignatureUpdates() override;
    bool downloadSignatureUpdate(const std::string& id) override;
    bool installSignatureUpdate(const std::string& id) override;

    // Version compatibility
    VersionCompatibility checkVersionCompatibility(const std::string& version) override;

    // History
    std::vector<UpdateHistoryEntry> getUpdateHistory() override;

    // Non-interface helpers for testing
    void addAvailableUpdate(const UpdateInfo& update);
    void addSignatureUpdate(const SignatureUpdate& update);
    void setCurrentVersion(const std::string& version);
    void setCompatibilityMatrix(const std::string& version, const VersionCompatibility& compat);

private:
    std::string generateId();
    std::string getCurrentTimestamp() const;

    mutable std::mutex mutex_;
    UpdateChannel channel_ = UpdateChannel::Stable;
    std::string currentVersion_ = "1.0.0";
    std::string previousVersion_;
    std::vector<UpdateInfo> availableUpdates_;
    std::unordered_map<std::string, UpdateProgress> progress_;
    std::unordered_map<std::string, StagedRollout> rollouts_;
    std::unordered_map<std::string, SignatureUpdate> signatureUpdates_;
    std::unordered_map<std::string, bool> signatureInstalled_;
    std::unordered_map<std::string, VersionCompatibility> compatibilityMatrix_;
    std::vector<UpdateHistoryEntry> history_;
    int nextId_ = 1;
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Updates
