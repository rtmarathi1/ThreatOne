#pragma once

#include "updates/IUpdateManager.h"
#include "core/Logger.h"

#include <mutex>
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace ThreatOne::Updates {

struct DeltaPatch {
    std::string id;
    std::string fromVersion;
    std::string toVersion;
    uint64_t patchSize = 0;
    uint64_t fullSize = 0;
    std::string checksum;
    std::string createdAt;
    bool verified = false;
};

struct DeltaApplyResult {
    bool success = false;
    std::string fromVersion;
    std::string toVersion;
    uint64_t bytesApplied = 0;
    std::string appliedAt;
    std::string errorMessage;
};

class DeltaUpdater {
public:
    DeltaUpdater();
    ~DeltaUpdater() = default;

    // Delta patch management
    std::string createDeltaPatch(const std::string& fromVersion, const std::string& toVersion,
                                 uint64_t patchSize, uint64_t fullSize);
    [[nodiscard]] std::optional<DeltaPatch> getDeltaPatch(const std::string& patchId) const;
    [[nodiscard]] std::vector<DeltaPatch> getAvailablePatches() const;
    [[nodiscard]] std::optional<DeltaPatch> findPatch(const std::string& fromVersion,
                                                      const std::string& toVersion) const;
    bool removePatch(const std::string& patchId);

    // Apply delta updates
    DeltaApplyResult applyDelta(const std::string& patchId);
    bool verifyPatch(const std::string& patchId, const std::string& checksum);

    // Size savings calculation
    [[nodiscard]] double calculateSavingsPercentage(const std::string& patchId) const;
    [[nodiscard]] uint64_t getTotalBytesSaved() const;

    // Statistics
    [[nodiscard]] uint64_t getTotalPatchesApplied() const;
    [[nodiscard]] uint64_t getTotalPatchesFailed() const;
    [[nodiscard]] uint64_t getPatchCount() const;

private:
    std::string generatePatchId();
    std::string getCurrentTimestamp() const;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, DeltaPatch> patches_;
    std::vector<DeltaApplyResult> applyHistory_;
    uint64_t totalBytesSaved_ = 0;
    uint64_t totalApplied_ = 0;
    uint64_t totalFailed_ = 0;
    int nextPatchId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Updates
