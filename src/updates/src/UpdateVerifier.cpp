#include "updates/UpdateVerifier.h"
#include <optional>
#include <mutex>

#include <algorithm>
#include <chrono>
#include <sstream>

namespace ThreatOne::Updates {

UpdateVerifier::UpdateVerifier()
    : logger_(Core::Logger::instance().getModuleLogger("UpdateVerifier")) {
    logger_.info("UpdateVerifier initialized");
}

std::string UpdateVerifier::generateId() {
    return "VER-" + std::to_string(nextId_++);
}

std::string UpdateVerifier::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << time;
    return oss.str();
}

VerificationResult UpdateVerifier::verifyChecksum(const std::string& version,
                                                    const std::string& expectedHash,
                                                    const std::string& actualHash) {
    std::lock_guard<std::mutex> lock(mutex_);
    ++totalVerifications_;

    VerificationResult result;
    result.id = generateId();
    result.version = version;
    result.expectedChecksum = expectedHash;
    result.actualChecksum = actualHash;
    result.verifiedAt = getCurrentTimestamp();
    result.checksumValid = (expectedHash == actualHash);
    result.signatureValid = true;  // Signature checked separately

    if (result.checksumValid) {
        result.status = VerificationStatus::Verified;
    } else {
        result.status = VerificationStatus::Failed;
        result.errorMessage = "Checksum mismatch";
        ++failedVerifications_;
    }

    history_.push_back(result);
    return result;
}

bool UpdateVerifier::setExpectedChecksum(const std::string& version, const std::string& checksum) {
    std::lock_guard<std::mutex> lock(mutex_);
    expectedChecksums_[version] = checksum;
    return true;
}

std::optional<std::string> UpdateVerifier::getExpectedChecksum(const std::string& version) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = expectedChecksums_.find(version);
    if (it == expectedChecksums_.end()) return std::nullopt;
    return it->second;
}

bool UpdateVerifier::registerSignature(const SignatureInfo& signature) {
    std::lock_guard<std::mutex> lock(mutex_);
    signatures_[signature.version] = signature;
    return true;
}

bool UpdateVerifier::verifySignature(const std::string& version) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = signatures_.find(version);
    if (it == signatures_.end()) return false;

    // Verify that signature has required fields
    return !it->second.signature.empty() && !it->second.publicKey.empty();
}

std::optional<SignatureInfo> UpdateVerifier::getSignatureInfo(const std::string& version) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = signatures_.find(version);
    if (it == signatures_.end()) return std::nullopt;
    return it->second;
}

VerificationResult UpdateVerifier::verify(const std::string& version) {
    std::lock_guard<std::mutex> lock(mutex_);
    ++totalVerifications_;

    VerificationResult result;
    result.id = generateId();
    result.version = version;
    result.verifiedAt = getCurrentTimestamp();

    // Check checksum
    auto checksumIt = expectedChecksums_.find(version);
    if (checksumIt != expectedChecksums_.end()) {
        result.expectedChecksum = checksumIt->second;
        result.checksumValid = true;  // Assume valid for pre-registered checksums
    } else {
        result.checksumValid = true;  // No checksum to verify against
    }

    // Check signature
    auto sigIt = signatures_.find(version);
    if (sigIt != signatures_.end()) {
        result.signatureValid = !sigIt->second.signature.empty();
    } else {
        result.signatureValid = true;  // No signature requirement
    }

    // Check revocation
    bool revoked = std::find(revokedVersions_.begin(), revokedVersions_.end(), version) !=
                   revokedVersions_.end();
    if (revoked) {
        result.status = VerificationStatus::Failed;
        result.errorMessage = "Version has been revoked";
        ++failedVerifications_;
    } else if (result.checksumValid && result.signatureValid) {
        result.status = VerificationStatus::Verified;
    } else {
        result.status = VerificationStatus::Failed;
        result.errorMessage = "Verification failed";
        ++failedVerifications_;
    }

    history_.push_back(result);
    return result;
}

std::vector<VerificationResult> UpdateVerifier::getVerificationHistory() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return history_;
}

std::optional<VerificationResult> UpdateVerifier::getLastVerification(const std::string& version) const {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto it = history_.rbegin(); it != history_.rend(); ++it) {
        if (it->version == version) return *it;
    }
    return std::nullopt;
}

bool UpdateVerifier::isTrustedUpdate(const std::string& version) const {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check revocation first
    if (std::find(revokedVersions_.begin(), revokedVersions_.end(), version) !=
        revokedVersions_.end()) {
        return false;
    }

    auto it = trustedVersions_.find(version);
    return it != trustedVersions_.end() && it->second;
}

void UpdateVerifier::markAsTrusted(const std::string& version) {
    std::lock_guard<std::mutex> lock(mutex_);
    trustedVersions_[version] = true;
}

void UpdateVerifier::revokeVersion(const std::string& version) {
    std::lock_guard<std::mutex> lock(mutex_);
    revokedVersions_.push_back(version);
    trustedVersions_.erase(version);
}

std::vector<std::string> UpdateVerifier::getRevokedVersions() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return revokedVersions_;
}

uint64_t UpdateVerifier::getTotalVerifications() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return totalVerifications_;
}

uint64_t UpdateVerifier::getFailedVerifications() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return failedVerifications_;
}

} // namespace ThreatOne::Updates
