#include "updates/DeltaUpdater.h"

#include <algorithm>
#include <chrono>
#include <sstream>

namespace ThreatOne::Updates {

DeltaUpdater::DeltaUpdater()
    : logger_(Core::Logger::instance().getModuleLogger("DeltaUpdater")) {
    logger_.info("DeltaUpdater initialized");
}

std::string DeltaUpdater::generatePatchId() {
    return "PATCH-" + std::to_string(nextPatchId_++);
}

std::string DeltaUpdater::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << time;
    return oss.str();
}

std::string DeltaUpdater::createDeltaPatch(const std::string& fromVersion,
                                            const std::string& toVersion,
                                            uint64_t patchSize, uint64_t fullSize) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = generatePatchId();
    DeltaPatch patch;
    patch.id = id;
    patch.fromVersion = fromVersion;
    patch.toVersion = toVersion;
    patch.patchSize = patchSize;
    patch.fullSize = fullSize;
    patch.createdAt = getCurrentTimestamp();
    patch.verified = false;

    patches_[id] = patch;
    logger_.info("Created delta patch: {} ({} -> {})", id, fromVersion, toVersion);
    return id;
}

std::optional<DeltaPatch> DeltaUpdater::getDeltaPatch(const std::string& patchId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = patches_.find(patchId);
    if (it == patches_.end()) return std::nullopt;
    return it->second;
}

std::vector<DeltaPatch> DeltaUpdater::getAvailablePatches() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<DeltaPatch> result;
    result.reserve(patches_.size());
    for (const auto& [id, patch] : patches_) {
        result.push_back(patch);
    }
    return result;
}

std::optional<DeltaPatch> DeltaUpdater::findPatch(const std::string& fromVersion,
                                                    const std::string& toVersion) const {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& [id, patch] : patches_) {
        if (patch.fromVersion == fromVersion && patch.toVersion == toVersion) {
            return patch;
        }
    }
    return std::nullopt;
}

bool DeltaUpdater::removePatch(const std::string& patchId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = patches_.find(patchId);
    if (it == patches_.end()) return false;
    patches_.erase(it);
    return true;
}

DeltaApplyResult DeltaUpdater::applyDelta(const std::string& patchId) {
    std::lock_guard<std::mutex> lock(mutex_);

    DeltaApplyResult result;
    auto it = patches_.find(patchId);
    if (it == patches_.end()) {
        result.success = false;
        result.errorMessage = "Patch not found";
        ++totalFailed_;
        applyHistory_.push_back(result);
        return result;
    }

    if (!it->second.verified) {
        result.success = false;
        result.fromVersion = it->second.fromVersion;
        result.toVersion = it->second.toVersion;
        result.errorMessage = "Patch not verified";
        ++totalFailed_;
        applyHistory_.push_back(result);
        return result;
    }

    result.success = true;
    result.fromVersion = it->second.fromVersion;
    result.toVersion = it->second.toVersion;
    result.bytesApplied = it->second.patchSize;
    result.appliedAt = getCurrentTimestamp();

    totalBytesSaved_ += (it->second.fullSize - it->second.patchSize);
    ++totalApplied_;
    applyHistory_.push_back(result);

    logger_.info("Applied delta patch: {} ({} -> {})", patchId,
                 result.fromVersion, result.toVersion);
    return result;
}

bool DeltaUpdater::verifyPatch(const std::string& patchId, const std::string& checksum) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = patches_.find(patchId);
    if (it == patches_.end()) return false;

    it->second.checksum = checksum;
    it->second.verified = true;
    return true;
}

double DeltaUpdater::calculateSavingsPercentage(const std::string& patchId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = patches_.find(patchId);
    if (it == patches_.end() || it->second.fullSize == 0) return 0.0;

    return (1.0 - static_cast<double>(it->second.patchSize) /
            static_cast<double>(it->second.fullSize)) * 100.0;
}

uint64_t DeltaUpdater::getTotalBytesSaved() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return totalBytesSaved_;
}

uint64_t DeltaUpdater::getTotalPatchesApplied() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return totalApplied_;
}

uint64_t DeltaUpdater::getTotalPatchesFailed() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return totalFailed_;
}

uint64_t DeltaUpdater::getPatchCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return patches_.size();
}

} // namespace ThreatOne::Updates
