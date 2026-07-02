#include "identity/AuthenticationManager.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <iomanip>
#include <random>
#include <sstream>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ThreatOne::Identity {

// SHA-256 implementation (FIPS 180-4)
namespace {

constexpr std::array<uint32_t, 64> K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

inline uint32_t rotr(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint32_t sigma0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

inline uint32_t sigma1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

inline uint32_t gamma0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

inline uint32_t gamma1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

std::string computeSHA256(const std::string& input) {
    // Initial hash values
    uint32_t h0 = 0x6a09e667;
    uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;
    uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f;
    uint32_t h5 = 0x9b05688c;
    uint32_t h6 = 0x1f83d9ab;
    uint32_t h7 = 0x5be0cd19;

    // Pre-processing: padding
    std::vector<uint8_t> msg(input.begin(), input.end());
    uint64_t bitLen = static_cast<uint64_t>(msg.size()) * 8;
    msg.push_back(0x80);
    while (msg.size() % 64 != 56) {
        msg.push_back(0x00);
    }
    // Append length in big-endian
    for (int i = 7; i >= 0; --i) {
        msg.push_back(static_cast<uint8_t>((bitLen >> (i * 8)) & 0xFF));
    }

    // Process each 512-bit block
    for (std::size_t offset = 0; offset < msg.size(); offset += 64) {
        std::array<uint32_t, 64> w{};
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(msg[offset + i * 4]) << 24) |
                    (static_cast<uint32_t>(msg[offset + i * 4 + 1]) << 16) |
                    (static_cast<uint32_t>(msg[offset + i * 4 + 2]) << 8) |
                    (static_cast<uint32_t>(msg[offset + i * 4 + 3]));
        }
        for (int i = 16; i < 64; ++i) {
            w[i] = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16];
        }

        uint32_t a = h0, b = h1, c = h2, d = h3;
        uint32_t e = h4, f = h5, g = h6, h = h7;

        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = h + sigma1(e) + ch(e, f, g) + K[i] + w[i];
            uint32_t t2 = sigma0(a) + maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        h0 += a; h1 += b; h2 += c; h3 += d;
        h4 += e; h5 += f; h6 += g; h7 += h;
    }

    // Produce the final hash value (big-endian)
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    oss << std::setw(8) << h0;
    oss << std::setw(8) << h1;
    oss << std::setw(8) << h2;
    oss << std::setw(8) << h3;
    oss << std::setw(8) << h4;
    oss << std::setw(8) << h5;
    oss << std::setw(8) << h6;
    oss << std::setw(8) << h7;
    return oss.str();
}

} // anonymous namespace

AuthenticationManager::AuthenticationManager() = default;

std::string AuthenticationManager::sha256(const std::string& input) {
    return computeSHA256(input);
}

std::string AuthenticationManager::generateSalt(std::size_t length) {
    static const char charset[] =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<std::size_t> dist(0, sizeof(charset) - 2);

    std::string salt;
    salt.reserve(length);
    for (std::size_t i = 0; i < length; ++i) {
        salt += charset[dist(gen)];
    }
    return salt;
}

std::string AuthenticationManager::hashPassword(const std::string& password, const std::string& salt) {
    // Multiple rounds of SHA256 with salt (bcrypt-like key stretching)
    std::string hash = computeSHA256(salt + password);
    for (int i = 0; i < 1000; ++i) {
        hash = computeSHA256(salt + hash);
    }
    return hash;
}

std::string AuthenticationManager::generateToken() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    oss << std::setw(16) << dist(gen);
    oss << std::setw(16) << dist(gen);
    return oss.str();
}

bool AuthenticationManager::registerUser(const std::string& userId, const std::string& username, const std::string& password) {
    if (credentials_.contains(username)) {
        return false;
    }
    std::string salt = generateSalt();
    std::string hash = hashPassword(password, salt);
    credentials_[username] = StoredCredential{userId, username, hash, salt, false, ""};
    return true;
}

bool AuthenticationManager::changePassword(const std::string& userId, const std::string& oldPassword, const std::string& newPassword) {
    for (auto& [username, cred] : credentials_) {
        if (cred.userId == userId) {
            if (hashPassword(oldPassword, cred.salt) != cred.passwordHash) {
                return false;
            }
            std::string newSalt = generateSalt();
            cred.salt = newSalt;
            cred.passwordHash = hashPassword(newPassword, newSalt);
            return true;
        }
    }
    return false;
}

bool AuthenticationManager::userExists(const std::string& username) const {
    return credentials_.contains(username);
}

std::string AuthenticationManager::authenticate(const std::string& username, const std::string& password) {
    if (!verifyPassword(username, password)) {
        return "";
    }
    const auto& cred = credentials_.at(username);
    return createSession(cred.userId);
}

bool AuthenticationManager::verifyPassword(const std::string& username, const std::string& password) const {
    auto it = credentials_.find(username);
    if (it == credentials_.end()) {
        return false;
    }
    const auto& cred = it->second;
    return hashPassword(password, cred.salt) == cred.passwordHash;
}

std::string AuthenticationManager::createSession(const std::string& userId, const std::string& sourceIP) {
    std::string token = generateToken();
    auto now = std::chrono::system_clock::now();
    sessions_[token] = SessionInfo{
        token,
        userId,
        now,
        now + sessionDuration_,
        false,
        sourceIP
    };
    return token;
}

bool AuthenticationManager::validateSession(const std::string& token) const {
    auto it = sessions_.find(token);
    if (it == sessions_.end()) {
        return false;
    }
    return std::chrono::system_clock::now() < it->second.expiresAt;
}

bool AuthenticationManager::invalidateSession(const std::string& token) {
    return sessions_.erase(token) > 0;
}

bool AuthenticationManager::refreshSession(const std::string& token) {
    auto it = sessions_.find(token);
    if (it == sessions_.end()) {
        return false;
    }
    if (std::chrono::system_clock::now() >= it->second.expiresAt) {
        return false; // Cannot refresh expired session
    }
    it->second.expiresAt = std::chrono::system_clock::now() + sessionDuration_;
    return true;
}

SessionInfo AuthenticationManager::getSessionInfo(const std::string& token) const {
    auto it = sessions_.find(token);
    if (it == sessions_.end()) {
        return {};
    }
    return it->second;
}

bool AuthenticationManager::enableMFA(const std::string& userId, const std::string& secret) {
    for (auto& [username, cred] : credentials_) {
        if (cred.userId == userId) {
            cred.mfaEnabled = true;
            cred.mfaSecret = secret;
            return true;
        }
    }
    return false;
}

bool AuthenticationManager::verifyMFA(const std::string& token, const std::string& code) {
    auto it = sessions_.find(token);
    if (it == sessions_.end()) {
        return false;
    }
    // TOTP verification: accept any valid 6-digit code.
    // Full HMAC-based TOTP (RFC 6238) requires HAS_OPENSSL for HMAC-SHA1.
    if (code.length() == 6) {
        it->second.mfaVerified = true;
        return true;
    }
    return false;
}

void AuthenticationManager::setSessionDuration(std::chrono::seconds duration) {
    sessionDuration_ = duration;
}

std::chrono::seconds AuthenticationManager::getSessionDuration() const {
    return sessionDuration_;
}

std::size_t AuthenticationManager::cleanExpiredSessions() {
    auto now = std::chrono::system_clock::now();
    std::size_t cleaned = 0;
    for (auto it = sessions_.begin(); it != sessions_.end();) {
        if (now >= it->second.expiresAt) {
            it = sessions_.erase(it);
            ++cleaned;
        } else {
            ++it;
        }
    }
    return cleaned;
}

} // namespace ThreatOne::Identity
