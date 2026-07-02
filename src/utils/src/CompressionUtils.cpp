#include "utils/CompressionUtils.h"
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#ifdef HAS_ZSTD
#include <zstd.h>
#endif

namespace ThreatOne::Utils {

#ifdef HAS_ZSTD

// ============================================================================
// Zstandard compression implementation
// ============================================================================

static int zstdLevel(CompressionLevel level) {
    switch (level) {
        case CompressionLevel::Fast:    return 1;
        case CompressionLevel::Default: return 3;
        case CompressionLevel::Best:    return 19;
    }
    return 3;
}

Core::Result<std::vector<uint8_t>, Core::Error> CompressionUtils::compress(
    const std::vector<uint8_t>& data,
    CompressionLevel level) {

    if (data.empty()) {
        return Core::Result<std::vector<uint8_t>, Core::Error>::ok(std::vector<uint8_t>{});
    }

    size_t bound = ZSTD_compressBound(data.size());
    std::vector<uint8_t> output(bound);

    size_t compressedSize = ZSTD_compress(
        output.data(), output.size(),
        data.data(), data.size(),
        zstdLevel(level));

    if (ZSTD_isError(compressedSize)) {
        return Core::Result<std::vector<uint8_t>, Core::Error>::err(
            Core::Error(std::string("Zstd compression failed: ") + ZSTD_getErrorName(compressedSize),
                       Core::ErrorCategory::Internal));
    }

    output.resize(compressedSize);
    return Core::Result<std::vector<uint8_t>, Core::Error>::ok(std::move(output));
}

Core::Result<std::vector<uint8_t>, Core::Error> CompressionUtils::decompress(
    const std::vector<uint8_t>& data) {

    if (data.empty()) {
        return Core::Result<std::vector<uint8_t>, Core::Error>::ok(std::vector<uint8_t>{});
    }

    // Get the decompressed size from the frame header
    unsigned long long decompressedSize = ZSTD_getFrameContentSize(data.data(), data.size());
    if (decompressedSize == ZSTD_CONTENTSIZE_ERROR) {
        return Core::Result<std::vector<uint8_t>, Core::Error>::err(
            Core::Error("Invalid Zstd compressed data", Core::ErrorCategory::Validation));
    }
    if (decompressedSize == ZSTD_CONTENTSIZE_UNKNOWN) {
        // Use streaming decompression fallback with a reasonable max
        decompressedSize = data.size() * 10; // Estimate
    }

    std::vector<uint8_t> output(static_cast<size_t>(decompressedSize));
    size_t actualSize = ZSTD_decompress(
        output.data(), output.size(),
        data.data(), data.size());

    if (ZSTD_isError(actualSize)) {
        return Core::Result<std::vector<uint8_t>, Core::Error>::err(
            Core::Error(std::string("Zstd decompression failed: ") + ZSTD_getErrorName(actualSize),
                       Core::ErrorCategory::Internal));
    }

    output.resize(actualSize);
    return Core::Result<std::vector<uint8_t>, Core::Error>::ok(std::move(output));
}

bool CompressionUtils::isCompressionAvailable() {
    return true;
}

std::string CompressionUtils::backendName() {
    return "zstd";
}

#else

// ============================================================================
// Passthrough fallback (no real compression)
// ============================================================================

Core::Result<std::vector<uint8_t>, Core::Error> CompressionUtils::compress(
    const std::vector<uint8_t>& data,
    CompressionLevel /*level*/) {

    // Passthrough: return data unchanged
    return Core::Result<std::vector<uint8_t>, Core::Error>::ok(data);
}

Core::Result<std::vector<uint8_t>, Core::Error> CompressionUtils::decompress(
    const std::vector<uint8_t>& data) {

    // Passthrough: return data unchanged
    return Core::Result<std::vector<uint8_t>, Core::Error>::ok(data);
}

bool CompressionUtils::isCompressionAvailable() {
    return false;
}

std::string CompressionUtils::backendName() {
    return "passthrough";
}

#endif // HAS_ZSTD

} // namespace ThreatOne::Utils
