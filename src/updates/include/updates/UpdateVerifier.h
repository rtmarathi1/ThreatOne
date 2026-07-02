#pragma once
#include <optional>

#include "updates/IUpdateManager.h"
#include "core/Logger.h"

#include <mutex>
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace ThreatOne::Updates {

enum class VerificationStatus {
    Pending,
    Verified,
    Failed,
    Skipped
};

struct VerificationResult {
    std::string id;
    std::string version;
    VerificationStatus status = VerificationStatus::Pending;
    bool checksumValid = false;
    bool signatureValid = false;
    std::string expectedChecksum;
    std::string actualChecksum;
    std::string verifiedAt;
    std::string errorMessage;
};

struct SignatureInfo {
    std::string version;
    std::string algorithm;  // SHA256, SHA512
    std::string publicKey;
    std::string signature;
    std::string timestamp;
};

class UpdateVerifier {
public:
    UpdateVerifier();
    ~UpdateVerifier() = default;

    // Checksum verification
    VerificationResult verifyChecksum(const std::string& version, const std::string& expectedHash,
                                      const std::string& actualHash);
    bool setExpectedChecksum(const std::string& version, const std::string& checksum);
    [[nodiscard]] std::optional<std::string> getExpectedChecksum(const std::string& version) const;

    // Signature verification
    bool registerSignature(const SignatureInfo& signature);
    bool verifySignature(const std::string& version) const;
    [[nodiscard]] std::optional<SignatureInfo> getSignatureInfo(const std::string& version) const;

    // Verification operations
    VerificationResult verify(const std::string& version);
    [[nodiscard]] std::vector<VerificationResult> getVerificationHistory() const;
    [[nodiscard]] std::optional<VerificationResult> getLastVerification(const std::string& version) const;

    // Trust
    bool isTrustedUpdate(const std::string& version) const;
    void markAsTrusted(const std::string& version);
    void revokeVersion(const std::string& version);
    [[nodiscard]] std::vector<std::string> getRevokedVersions() const;

    // Statistics
    [[nodiscard]] uint64_t getTotalVerifications() const;
    [[nodiscard]] uint64_t getFailedVerifications() const;

private:
    std::string generateId();
    std::string getCurrentTimestamp() const;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::string> expectedChecksums_; // version -> checksum
    std::unordered_map<std::string, SignatureInfo> signatures_; // version -> signature
    std::vector<VerificationResult> history_;
    std::unordered_map<std::string, bool> trustedVersions_;
    std::vector<std::string> revokedVersions_;
    uint64_t totalVerifications_ = 0;
    uint64_t failedVerifications_ = 0;
    int nextId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Updates
