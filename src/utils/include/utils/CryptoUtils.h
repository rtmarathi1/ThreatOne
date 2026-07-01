#pragma once

// ============================================================================
// WARNING: PLACEHOLDER IMPLEMENTATION - NOT CRYPTOGRAPHICALLY SECURE
//
// This module provides stub implementations for cryptographic operations.
// The hash function uses a simple polynomial hash (NOT SHA-256).
// The encryption uses XOR (NOT AES-256).
//
// DO NOT use this in production or trust the output for security purposes.
// These stubs exist only to satisfy the interface contract during Phase 1.
// They will be replaced by real cryptographic implementations (e.g., OpenSSL,
// libsodium) in a future phase.
// ============================================================================

#include <string>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <random>
#include <sstream>
#include <iomanip>

namespace ThreatOne::Utils {

// Hash algorithm identifiers.
// IMPORTANT: Current implementations are NON-CRYPTOGRAPHIC placeholders.
// The _PLACEHOLDER suffix indicates these do not provide real cryptographic hashing.
enum class HashAlgorithm {
    SHA256_PLACEHOLDER,   // Stub: uses polynomial hash, NOT real SHA-256
    BLAKE3_PLACEHOLDER    // Stub: uses polynomial hash, NOT real BLAKE3
};

// Encryption algorithm identifiers.
// IMPORTANT: Current implementations are NON-CRYPTOGRAPHIC placeholders.
// The _PLACEHOLDER suffix indicates these do not provide real encryption.
enum class EncryptionAlgorithm {
    AES256_PLACEHOLDER    // Stub: uses XOR, NOT real AES-256
};

class CryptoUtils {
public:
    // WARNING: This is NOT a real cryptographic hash. It uses a simple polynomial
    // hash that produces a 64-character hex string. Do not rely on collision
    // resistance or pre-image resistance.
    static std::string hash(const std::string& data, HashAlgorithm algorithm = HashAlgorithm::SHA256_PLACEHOLDER) {
        (void)algorithm;
        uint64_t h1 = 0, h2 = 0;
        for (size_t i = 0; i < data.size(); ++i) {
            h1 = h1 * 31 + static_cast<uint64_t>(static_cast<unsigned char>(data[i]));
            h2 = h2 * 37 + static_cast<uint64_t>(static_cast<unsigned char>(data[i]));
        }
        std::ostringstream ss;
        ss << std::hex << std::setfill('0')
           << std::setw(16) << h1
           << std::setw(16) << h2
           << std::setw(16) << (h1 ^ h2)
           << std::setw(16) << (h1 + h2);
        return ss.str();
    }

    // WARNING: This is NOT real encryption. It uses XOR with the key, which provides
    // no security whatsoever. Data "encrypted" with this function is trivially recoverable.
    static std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data,
                                         const std::vector<uint8_t>& key,
                                         EncryptionAlgorithm algorithm = EncryptionAlgorithm::AES256_PLACEHOLDER) {
        (void)algorithm;
        std::vector<uint8_t> result = data;
        for (size_t i = 0; i < result.size(); ++i) {
            result[i] ^= key[i % key.size()];
        }
        return result;
    }

    // WARNING: This is NOT real decryption. See encrypt() warning above.
    static std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data,
                                         const std::vector<uint8_t>& key,
                                         EncryptionAlgorithm algorithm = EncryptionAlgorithm::AES256_PLACEHOLDER) {
        // XOR is its own inverse
        return encrypt(data, key, algorithm);
    }

    // Generates random bytes using std::random_device + mt19937.
    // NOTE: std::random_device quality is implementation-defined and may not
    // be suitable for cryptographic key generation on all platforms.
    static std::vector<uint8_t> generateKey(size_t length = 32) {
        std::vector<uint8_t> key(length);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint16_t> dist(0, 255);
        for (auto& byte : key) {
            byte = static_cast<uint8_t>(dist(gen));
        }
        return key;
    }

    // Generates a random UUID v4. Uses mt19937 seeded with std::random_device.
    static std::string generateUUID() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFF);

        uint32_t p1 = dist(gen);
        uint16_t p2 = static_cast<uint16_t>(dist(gen) & 0xFFFF);
        uint16_t p3 = static_cast<uint16_t>((dist(gen) & 0x0FFF) | 0x4000); // Version 4
        uint16_t p4 = static_cast<uint16_t>((dist(gen) & 0x3FFF) | 0x8000); // Variant 1
        uint32_t p5a = dist(gen);
        uint16_t p5b = static_cast<uint16_t>(dist(gen) & 0xFFFF);

        char buf[37];
        std::snprintf(buf, sizeof(buf),
                      "%08x-%04x-%04x-%04x-%08x%04x",
                      p1, p2, p3, p4, p5a, p5b);
        return std::string(buf);
    }
};

} // namespace ThreatOne::Utils
