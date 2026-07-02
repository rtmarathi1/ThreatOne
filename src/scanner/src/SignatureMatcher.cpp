#include "scanner/SignatureMatcher.h"
#include <cstdint>
#include <string>
#include <vector>

namespace ThreatOne::Scanner {

SignatureMatcher::SignatureMatcher(SignatureDatabase& sigDb)
    : sigDb_(sigDb) {
}

Core::Result<MatchResult, Core::Error> SignatureMatcher::matchFile(
    const std::filesystem::path& filePath,
    HashAlgorithm algorithm) {

    auto hashResult = FileHasher::hashFile(filePath, algorithm);
    if (hashResult.isErr()) {
        return Core::Result<MatchResult, Core::Error>::err(hashResult.error());
    }

    MatchResult result;
    result.filePath = filePath.string();
    result.fileHash = hashResult.value();

    auto sig = sigDb_.lookupByHash(result.fileHash);
    if (sig.has_value()) {
        result.matched = true;
        result.signature = sig.value();
    }

    return Core::Result<MatchResult, Core::Error>::ok(result);
}

Core::Result<MatchResult, Core::Error> SignatureMatcher::matchBuffer(
    const std::vector<uint8_t>& data,
    HashAlgorithm algorithm) {

    auto hashResult = FileHasher::hashBuffer(data, algorithm);
    if (hashResult.isErr()) {
        return Core::Result<MatchResult, Core::Error>::err(hashResult.error());
    }

    MatchResult result;
    result.fileHash = hashResult.value();

    auto sig = sigDb_.lookupByHash(result.fileHash);
    if (sig.has_value()) {
        result.matched = true;
        result.signature = sig.value();
    }

    return Core::Result<MatchResult, Core::Error>::ok(result);
}

MatchResult SignatureMatcher::matchHash(const std::string& hash, const std::string& sourcePath) {
    MatchResult result;
    result.filePath = sourcePath;
    result.fileHash = hash;

    auto sig = sigDb_.lookupByHash(hash);
    if (sig.has_value()) {
        result.matched = true;
        result.signature = sig.value();
    }

    return result;
}

} // namespace ThreatOne::Scanner
