#pragma once

// ThreatOne Utils - Compression Utilities
//
// Provides data compression/decompression with multiple backends:
// - HAS_ZSTD: Zstandard compression via libzstd (production-grade)
// - Fallback: Passthrough (returns data unchanged)

#include <vector>
#include <cstdint>
#include <string>

#include <core/Error.h>

namespace ThreatOne::Utils {

// Compression level presets
enum class CompressionLevel {
    Fast,       // Fastest compression, lower ratio
    Default,    // Balanced speed/ratio
    Best        // Best ratio, slower compression
};

// Compression utilities with optional Zstandard backend
class CompressionUtils {
public:
    // Compress data
    // When HAS_ZSTD: uses ZSTD_compress
    // Fallback: returns data unchanged (passthrough)
    static Core::Result<std::vector<uint8_t>, Core::Error> compress(
        const std::vector<uint8_t>& data,
        CompressionLevel level = CompressionLevel::Default);

    // Decompress data
    // When HAS_ZSTD: uses ZSTD_decompress
    // Fallback: returns data unchanged (passthrough)
    static Core::Result<std::vector<uint8_t>, Core::Error> decompress(
        const std::vector<uint8_t>& data);

    // Check if real compression is available
    static bool isCompressionAvailable();

    // Get the name of the active compression backend
    static std::string backendName();
};

} // namespace ThreatOne::Utils
