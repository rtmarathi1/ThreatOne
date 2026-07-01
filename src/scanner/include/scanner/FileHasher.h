#pragma once

// ThreatOne Scanner - File Hashing
// When HAS_OPENSSL is defined: uses OpenSSL EVP API for SHA256
// Otherwise: uses custom FIPS 180-4 SHA256 implementation (no external library needed)
// BLAKE3 placeholder for future implementation

#include <string>
#include <vector>
#include <cstdint>
#include <array>
#include <filesystem>

#include <core/Error.h>

#ifdef HAS_OPENSSL
#include <openssl/evp.h>
#endif

namespace ThreatOne::Scanner {

// Hash algorithm selection
enum class HashAlgorithm {
    SHA256,
    BLAKE3  // Placeholder - returns a simplified hash
};

#ifdef HAS_OPENSSL

// SHA256 implementation using OpenSSL EVP API
class SHA256 {
public:
    SHA256();
    ~SHA256();

    // Non-copyable
    SHA256(const SHA256&) = delete;
    SHA256& operator=(const SHA256&) = delete;

    void update(const uint8_t* data, size_t length);
    void update(const std::string& data);
    std::array<uint8_t, 32> finalize();

    static std::array<uint8_t, 32> hash(const uint8_t* data, size_t length);
    static std::array<uint8_t, 32> hash(const std::string& data);

private:
    EVP_MD_CTX* ctx_;
};

#else

// SHA256 implementation per FIPS 180-4 (fallback when OpenSSL is not available)
class SHA256 {
public:
    SHA256();

    void update(const uint8_t* data, size_t length);
    void update(const std::string& data);
    std::array<uint8_t, 32> finalize();

    static std::array<uint8_t, 32> hash(const uint8_t* data, size_t length);
    static std::array<uint8_t, 32> hash(const std::string& data);

private:
    void processBlock(const uint8_t* block);

    std::array<uint32_t, 8> state_;
    uint64_t bitCount_;
    std::array<uint8_t, 64> buffer_;
    size_t bufferLength_;
};

#endif // HAS_OPENSSL

// File hashing utility
class FileHasher {
public:
    // Hash a file by path, reading in chunks
    static Core::Result<std::string, Core::Error> hashFile(
        const std::filesystem::path& filePath,
        HashAlgorithm algorithm = HashAlgorithm::SHA256);

    // Hash raw byte buffer
    static Core::Result<std::string, Core::Error> hashBuffer(
        const std::vector<uint8_t>& data,
        HashAlgorithm algorithm = HashAlgorithm::SHA256);

    // Hash a string
    static Core::Result<std::string, Core::Error> hashString(
        const std::string& data,
        HashAlgorithm algorithm = HashAlgorithm::SHA256);

private:
    // Convert bytes to hex string
    static std::string toHex(const std::array<uint8_t, 32>& bytes);

    // BLAKE3 placeholder hash
    static std::array<uint8_t, 32> blake3Placeholder(const uint8_t* data, size_t length);
};

} // namespace ThreatOne::Scanner
