#pragma once

// ThreatOne Utils - Cryptographic Utilities
//
// Provides authenticated encryption and key generation with multiple backends:
// - HAS_OPENSSL: AES-256-GCM via OpenSSL EVP API (production-grade)
// - HAS_LIBSODIUM: XChaCha20-Poly1305 via libsodium (production-grade)
// - Fallback: XOR cipher (NOT FOR PRODUCTION - development/testing only)

#include <string>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <random>
#include <sstream>
#include <iomanip>
#include <stdexcept>

#ifdef HAS_OPENSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif

#ifdef HAS_LIBSODIUM
#include <sodium.h>
#endif

namespace ThreatOne::Utils {

// Encryption backend selection
enum class CryptoBackend {
#ifdef HAS_OPENSSL
    AES_256_GCM,          // OpenSSL AES-256-GCM authenticated encryption
#endif
#ifdef HAS_LIBSODIUM
    XCHACHA20_POLY1305,   // libsodium XChaCha20-Poly1305 AEAD
#endif
    XOR_PLACEHOLDER       // NOT FOR PRODUCTION - XOR fallback for testing only
};

// Hash algorithm identifiers.
enum class HashAlgorithm {
    SHA256_PLACEHOLDER,   // Stub: uses polynomial hash, NOT real SHA-256
    BLAKE3_PLACEHOLDER    // Stub: uses polynomial hash, NOT real BLAKE3
};

class CryptoUtils {
public:
    // ========================================================================
    // Hashing (placeholder - use scanner/FileHasher for real SHA256)
    // ========================================================================

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

    // ========================================================================
    // Authenticated Encryption
    // ========================================================================

#ifdef HAS_OPENSSL
    // AES-256-GCM encryption using OpenSSL EVP API
    // Returns: [12-byte IV | ciphertext | 16-byte tag]
    static std::vector<uint8_t> encryptAesGcm(const std::vector<uint8_t>& plaintext,
                                               const std::vector<uint8_t>& key) {
        if (key.size() != 32) {
            throw std::invalid_argument("AES-256-GCM requires a 32-byte key");
        }

        // Generate random 12-byte IV
        std::vector<uint8_t> iv(12);
        RAND_bytes(iv.data(), static_cast<int>(iv.size()));

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create cipher context");
        }

        int len = 0;
        int ciphertextLen = 0;
        std::vector<uint8_t> ciphertext(plaintext.size() + 16); // Room for potential padding

        // Initialize encryption
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());

        // Encrypt
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(),
                         static_cast<int>(plaintext.size()));
        ciphertextLen = len;

        // Finalize
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
        ciphertextLen += len;
        ciphertext.resize(static_cast<size_t>(ciphertextLen));

        // Get the authentication tag
        std::vector<uint8_t> tag(16);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());

        EVP_CIPHER_CTX_free(ctx);

        // Output: IV | ciphertext | tag
        std::vector<uint8_t> output;
        output.reserve(iv.size() + ciphertext.size() + tag.size());
        output.insert(output.end(), iv.begin(), iv.end());
        output.insert(output.end(), ciphertext.begin(), ciphertext.end());
        output.insert(output.end(), tag.begin(), tag.end());

        return output;
    }

    // AES-256-GCM decryption using OpenSSL EVP API
    // Input: [12-byte IV | ciphertext | 16-byte tag]
    static std::vector<uint8_t> decryptAesGcm(const std::vector<uint8_t>& data,
                                               const std::vector<uint8_t>& key) {
        if (key.size() != 32) {
            throw std::invalid_argument("AES-256-GCM requires a 32-byte key");
        }
        if (data.size() < 28) { // 12 IV + 0 ciphertext + 16 tag minimum
            throw std::invalid_argument("Ciphertext too short");
        }

        // Extract IV, ciphertext, and tag
        std::vector<uint8_t> iv(data.begin(), data.begin() + 12);
        std::vector<uint8_t> ciphertext(data.begin() + 12, data.end() - 16);
        std::vector<uint8_t> tag(data.end() - 16, data.end());

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create cipher context");
        }

        int len = 0;
        int plaintextLen = 0;
        std::vector<uint8_t> plaintext(ciphertext.size());

        // Initialize decryption
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());

        // Decrypt
        EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(),
                         static_cast<int>(ciphertext.size()));
        plaintextLen = len;

        // Set the tag for verification
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                           const_cast<uint8_t*>(tag.data()));

        // Finalize and verify tag
        int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
        EVP_CIPHER_CTX_free(ctx);

        if (ret <= 0) {
            throw std::runtime_error("AES-GCM authentication failed");
        }
        plaintextLen += len;
        plaintext.resize(static_cast<size_t>(plaintextLen));

        return plaintext;
    }
#endif // HAS_OPENSSL

#ifdef HAS_LIBSODIUM
    // XChaCha20-Poly1305 encryption using libsodium
    // Returns: [24-byte nonce | ciphertext + 16-byte mac]
    static std::vector<uint8_t> encryptXChaCha20(const std::vector<uint8_t>& plaintext,
                                                  const std::vector<uint8_t>& key) {
        if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
            throw std::invalid_argument("XChaCha20-Poly1305 requires a 32-byte key");
        }

        // Generate random nonce
        std::vector<uint8_t> nonce(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        randombytes_buf(nonce.data(), nonce.size());

        // Encrypt
        std::vector<uint8_t> ciphertext(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
        unsigned long long ciphertextLen = 0;

        crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext.data(), &ciphertextLen,
            plaintext.data(), plaintext.size(),
            nullptr, 0,  // No additional data
            nullptr,     // nsec (unused)
            nonce.data(), key.data());

        ciphertext.resize(static_cast<size_t>(ciphertextLen));

        // Output: nonce | ciphertext (includes MAC)
        std::vector<uint8_t> output;
        output.reserve(nonce.size() + ciphertext.size());
        output.insert(output.end(), nonce.begin(), nonce.end());
        output.insert(output.end(), ciphertext.begin(), ciphertext.end());

        return output;
    }

    // XChaCha20-Poly1305 decryption using libsodium
    // Input: [24-byte nonce | ciphertext + 16-byte mac]
    static std::vector<uint8_t> decryptXChaCha20(const std::vector<uint8_t>& data,
                                                  const std::vector<uint8_t>& key) {
        if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
            throw std::invalid_argument("XChaCha20-Poly1305 requires a 32-byte key");
        }

        size_t nonceSize = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        if (data.size() < nonceSize + crypto_aead_xchacha20poly1305_ietf_ABYTES) {
            throw std::invalid_argument("Ciphertext too short");
        }

        // Extract nonce and ciphertext
        const uint8_t* nonce = data.data();
        const uint8_t* ciphertext = data.data() + nonceSize;
        size_t ciphertextLen = data.size() - nonceSize;

        std::vector<uint8_t> plaintext(ciphertextLen - crypto_aead_xchacha20poly1305_ietf_ABYTES);
        unsigned long long plaintextLen = 0;

        int ret = crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &plaintextLen,
            nullptr,  // nsec (unused)
            ciphertext, ciphertextLen,
            nullptr, 0,  // No additional data
            nonce, key.data());

        if (ret != 0) {
            throw std::runtime_error("XChaCha20-Poly1305 authentication failed");
        }

        plaintext.resize(static_cast<size_t>(plaintextLen));
        return plaintext;
    }

    // Derive a key from a password using Argon2id (libsodium crypto_pwhash)
    static std::vector<uint8_t> deriveKey(const std::string& password,
                                           const std::vector<uint8_t>& salt,
                                           size_t keyLength = 32) {
        if (salt.size() != crypto_pwhash_SALTBYTES) {
            throw std::invalid_argument("Salt must be " +
                std::to_string(crypto_pwhash_SALTBYTES) + " bytes");
        }

        std::vector<uint8_t> key(keyLength);
        int ret = crypto_pwhash(
            key.data(), key.size(),
            password.c_str(), password.size(),
            salt.data(),
            crypto_pwhash_OPSLIMIT_MODERATE,
            crypto_pwhash_MEMLIMIT_MODERATE,
            crypto_pwhash_ALG_ARGON2ID13);

        if (ret != 0) {
            throw std::runtime_error("Key derivation failed (out of memory?)");
        }

        return key;
    }

    // Secure memory wiping using libsodium
    static void secureZero(void* ptr, size_t len) {
        sodium_memzero(ptr, len);
    }
#endif // HAS_LIBSODIUM

    // ========================================================================
    // XOR Fallback - NOT FOR PRODUCTION
    // ========================================================================

    // WARNING: This is NOT real encryption. It uses XOR with the key, which provides
    // no security whatsoever. Data "encrypted" with this function is trivially recoverable.
    // This exists only to satisfy the interface contract when no crypto library is available.
    static std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data,
                                         const std::vector<uint8_t>& key) {
        std::vector<uint8_t> result = data;
        for (size_t i = 0; i < result.size(); ++i) {
            result[i] ^= key[i % key.size()];
        }
        return result;
    }

    // WARNING: This is NOT real decryption. See encrypt() warning above.
    static std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data,
                                         const std::vector<uint8_t>& key) {
        // XOR is its own inverse
        return encrypt(data, key);
    }

    // ========================================================================
    // Key Generation
    // ========================================================================

    // Generates random bytes.
    // When HAS_OPENSSL: uses RAND_bytes (cryptographically secure)
    // When HAS_LIBSODIUM: uses randombytes_buf (cryptographically secure)
    // Otherwise: uses std::random_device + mt19937 (quality is implementation-defined)
    static std::vector<uint8_t> generateKey(size_t length = 32) {
        std::vector<uint8_t> key(length);
#ifdef HAS_OPENSSL
        RAND_bytes(key.data(), static_cast<int>(length));
#elif defined(HAS_LIBSODIUM)
        randombytes_buf(key.data(), length);
#else
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint16_t> dist(0, 255);
        for (auto& byte : key) {
            byte = static_cast<uint8_t>(dist(gen));
        }
#endif
        return key;
    }

    // Generates a random UUID v4.
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
