#pragma once

// ThreatOne Scanner - Signature Matcher
// Computes file hashes and looks them up in the signature database

#include <string>
#include <filesystem>
#include <optional>

#include <core/Error.h>
#include "scanner/FileHasher.h"
#include "scanner/SignatureDatabase.h"
#include <cstdint>
#include <vector>

namespace ThreatOne::Scanner {

// Result of matching a file against signatures
struct MatchResult {
    bool matched = false;
    std::string filePath;
    std::string fileHash;
    std::optional<Signature> signature;  // populated if matched
};

// Matches files against signature database
class SignatureMatcher {
public:
    explicit SignatureMatcher(SignatureDatabase& sigDb);

    // Match a file against the signature database
    Core::Result<MatchResult, Core::Error> matchFile(
        const std::filesystem::path& filePath,
        HashAlgorithm algorithm = HashAlgorithm::SHA256);

    // Match a buffer against the signature database
    Core::Result<MatchResult, Core::Error> matchBuffer(
        const std::vector<uint8_t>& data,
        HashAlgorithm algorithm = HashAlgorithm::SHA256);

    // Match with a pre-computed hash
    MatchResult matchHash(const std::string& hash, const std::string& sourcePath = "");

private:
    SignatureDatabase& sigDb_;
};

} // namespace ThreatOne::Scanner
