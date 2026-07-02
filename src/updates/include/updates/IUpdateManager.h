#pragma once

// ThreatOne Updates - Update Manager Interface
// Update lifecycle, channels, staged rollouts, signature updates, version compatibility

#include <string>
#include <vector>
#include <optional>
#include <cstdint>

namespace ThreatOne::Updates {

enum class UpdateChannel {
    Stable,
    Beta,
    Nightly
};

enum class UpdateStatus {
    Available,
    Downloading,
    Downloaded,
    Installing,
    Installed,
    Failed,
    RolledBack
};

struct UpdateInfo {
    std::string version;
    std::string description;
    std::string releaseDate;
    uint64_t size = 0;
    bool critical = false;
    UpdateChannel channel = UpdateChannel::Stable;
};

struct VersionInfo {
    std::string current;
    std::string latest;
    bool updateAvailable = false;
};

struct StagedRollout {
    std::string id;
    std::string version;
    int percentage = 0;
    std::string startedAt;
    UpdateStatus status = UpdateStatus::Available;
};

struct SignatureUpdate {
    std::string id;
    std::string type;  // YARA, IOC, Signature
    std::string version;
    uint64_t size = 0;
    std::string hash;
    std::string timestamp;
};

struct VersionCompatibility {
    std::string minVersion;
    std::string maxVersion;
    bool compatible = false;
    std::string notes;
};

struct UpdateProgress {
    std::string version;
    UpdateStatus status = UpdateStatus::Available;
    uint64_t bytesDownloaded = 0;
    uint64_t totalBytes = 0;
    double percentage = 0.0;
};

struct UpdateHistoryEntry {
    std::string version;
    UpdateStatus status = UpdateStatus::Installed;
    std::string timestamp;
    std::string description;
};

class IUpdateManager {
public:
    virtual ~IUpdateManager() = default;

    // Core update operations
    virtual std::vector<UpdateInfo> checkForUpdates() = 0;
    virtual bool downloadUpdate(const std::string& version) = 0;
    virtual bool installUpdate(const std::string& version) = 0;
    virtual VersionInfo getVersion() = 0;
    virtual bool rollback() = 0;
    virtual bool cancelUpdate(const std::string& version) = 0;

    // Channel management
    virtual void setUpdateChannel(UpdateChannel channel) = 0;
    [[nodiscard]] virtual UpdateChannel getUpdateChannel() const = 0;

    // Progress tracking
    virtual std::optional<UpdateProgress> getUpdateProgress(const std::string& version) = 0;

    // Staged rollouts
    virtual std::optional<StagedRollout> stageRollout(const std::string& version, int percentage) = 0;

    // Signature updates
    virtual std::vector<SignatureUpdate> getSignatureUpdates() = 0;
    virtual bool downloadSignatureUpdate(const std::string& id) = 0;
    virtual bool installSignatureUpdate(const std::string& id) = 0;

    // Version compatibility
    virtual VersionCompatibility checkVersionCompatibility(const std::string& version) = 0;

    // History
    virtual std::vector<UpdateHistoryEntry> getUpdateHistory() = 0;
};

} // namespace ThreatOne::Updates
