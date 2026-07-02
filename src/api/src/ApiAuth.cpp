#include "api/ApiAuth.h"
#include <algorithm>
#include <random>
#include <sstream>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace ThreatOne::Api {

using json = nlohmann::json;

ApiAuth::ApiAuth() = default;

std::string ApiAuth::generateRandomKey() const {
    static const char chars[] =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, sizeof(chars) - 2);

    std::string key;
    key.reserve(32);
    for (int i = 0; i < 32; ++i) {
        key += chars[dist(gen)];
    }
    return "tk_" + key;
}

std::string ApiAuth::generateId() const {
    static const char chars[] = "0123456789abcdef";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, 15);

    std::string id;
    id.reserve(16);
    for (int i = 0; i < 16; ++i) {
        id += chars[dist(gen)];
    }
    return id;
}

std::string ApiAuth::base64Encode(const std::string& input) const {
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded;
    int val = 0;
    int bits = -6;
    const unsigned int mask = 0x3F;

    for (unsigned char c : input) {
        val = (val << 8) + c;
        bits += 8;
        while (bits >= 0) {
            encoded.push_back(table[(val >> bits) & mask]);
            bits -= 6;
        }
    }
    if (bits > -6) {
        encoded.push_back(table[((val << 8) >> (bits + 8)) & mask]);
    }
    while (encoded.size() % 4) {
        encoded.push_back('=');
    }
    return encoded;
}

std::string ApiAuth::base64Decode(const std::string& input) const {
    static const int table[] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1
    };

    std::string decoded;
    int val = 0;
    int bits = -8;

    for (unsigned char c : input) {
        if (c == '=') break;
        if (c >= 128 || table[c] == -1) continue;
        val = (val << 6) + table[c];
        bits += 6;
        if (bits >= 0) {
            decoded.push_back(static_cast<char>((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return decoded;
}

std::string ApiAuth::computeSignature(const std::string& data, const std::string& secret) const {
    // Simple HMAC-like signature (XOR-based for demonstration)
    std::string combined = data + secret;
    unsigned int hash = 0;
    for (char c : combined) {
        hash = hash * 31 + static_cast<unsigned char>(c);
    }
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(8) << hash;
    return oss.str();
}

ApiKey ApiAuth::generateApiKey(const std::string& name,
                                const std::vector<std::string>& permissions,
                                int rateLimit, int validDays) {
    std::lock_guard<std::mutex> lock(mutex_);

    ApiKey apiKey;
    apiKey.id = generateId();
    apiKey.key = generateRandomKey();
    apiKey.name = name;
    apiKey.permissions = permissions;
    apiKey.rateLimit = rateLimit;
    apiKey.createdAt = std::chrono::system_clock::now();
    apiKey.expiresAt = apiKey.createdAt + std::chrono::hours(24 * validDays);

    keys_[apiKey.key] = apiKey;
    idToKey_[apiKey.id] = apiKey.key;

    return apiKey;
}

bool ApiAuth::validateApiKey(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = keys_.find(key);
    if (it == keys_.end()) {
        return false;
    }

    // Check expiration
    auto now = std::chrono::system_clock::now();
    if (now >= it->second.expiresAt) {
        return false;
    }

    return true;
}

bool ApiAuth::revokeApiKey(const std::string& keyId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto idIt = idToKey_.find(keyId);
    if (idIt == idToKey_.end()) {
        return false;
    }

    keys_.erase(idIt->second);
    idToKey_.erase(idIt);
    return true;
}

std::optional<ApiKey> ApiAuth::getApiKeyInfo(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = keys_.find(key);
    if (it == keys_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::string ApiAuth::generateJwt(const JwtPayload& payload, const std::string& secret) {
    // Header
    json header;
    header["alg"] = "HS256";
    header["typ"] = "JWT";
    std::string headerEncoded = base64Encode(header.dump());

    // Payload
    json payloadJson;
    payloadJson["sub"] = payload.subject;
    payloadJson["iss"] = payload.issuer;
    payloadJson["aud"] = payload.audience;
    payloadJson["iat"] = std::chrono::duration_cast<std::chrono::seconds>(
        payload.issuedAt.time_since_epoch()).count();
    payloadJson["exp"] = std::chrono::duration_cast<std::chrono::seconds>(
        payload.expiresAt.time_since_epoch()).count();
    for (const auto& [k, v] : payload.claims) {
        payloadJson[k] = v;
    }
    std::string payloadEncoded = base64Encode(payloadJson.dump());

    // Signature
    std::string sigInput = headerEncoded + "." + payloadEncoded;
    std::string signature = base64Encode(computeSignature(sigInput, secret));

    return headerEncoded + "." + payloadEncoded + "." + signature;
}

JwtValidationResult ApiAuth::validateJwt(const std::string& token, const std::string& secret) const {
    JwtValidationResult result;

    // Split token into parts
    std::vector<std::string> parts;
    std::istringstream stream(token);
    std::string part;
    while (std::getline(stream, part, '.')) {
        parts.push_back(part);
    }

    if (parts.size() != 3) {
        result.valid = false;
        result.error = "Invalid token format: expected 3 parts";
        return result;
    }

    // Verify signature
    std::string sigInput = parts[0] + "." + parts[1];
    std::string expectedSig = base64Encode(computeSignature(sigInput, secret));

    if (parts[2] != expectedSig) {
        result.valid = false;
        result.error = "Invalid signature";
        return result;
    }

    // Decode payload
    std::string payloadStr = base64Decode(parts[1]);
    json payloadJson;
    try {
        payloadJson = json::parse(payloadStr);
    } catch (const std::exception&) {
        result.valid = false;
        result.error = "Invalid payload encoding";
        return result;
    }

    // Check expiration
    if (payloadJson.contains("exp")) {
        auto expTime = std::chrono::system_clock::time_point(
            std::chrono::seconds(payloadJson["exp"].get<int64_t>()));
        if (std::chrono::system_clock::now() >= expTime) {
            result.valid = false;
            result.error = "Token expired";
            return result;
        }
    }

    // Fill in the payload
    result.valid = true;
    result.payload.subject = payloadJson.value("sub", "");
    result.payload.issuer = payloadJson.value("iss", "");
    result.payload.audience = payloadJson.value("aud", "");
    if (payloadJson.contains("iat")) {
        result.payload.issuedAt = std::chrono::system_clock::time_point(
            std::chrono::seconds(payloadJson["iat"].get<int64_t>()));
    }
    if (payloadJson.contains("exp")) {
        result.payload.expiresAt = std::chrono::system_clock::time_point(
            std::chrono::seconds(payloadJson["exp"].get<int64_t>()));
    }

    return result;
}

bool ApiAuth::checkRateLimit(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto keyIt = keys_.find(key);
    if (keyIt == keys_.end()) {
        return false;
    }

    auto now = std::chrono::system_clock::now();
    auto& info = rateLimits_[key];

    // Initialize if this is a new entry (windowStart will be epoch/default)
    if (info.windowStart == std::chrono::system_clock::time_point{}) {
        info.maxRequests = keyIt->second.rateLimit;
        info.windowSeconds = 60;
        info.windowStart = now;
        info.currentCount = 0;
    }

    // Check if window has expired
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - info.windowStart).count();
    if (elapsed >= info.windowSeconds) {
        // Sliding window: reset
        info.windowStart = now;
        info.currentCount = 0;
    }

    // Check limit
    if (info.currentCount >= info.maxRequests) {
        return false; // Rate limited
    }

    info.currentCount++;
    return true;
}

RateLimitInfo ApiAuth::getRateLimitInfo(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = rateLimits_.find(key);
    if (it == rateLimits_.end()) {
        RateLimitInfo info;
        auto keyIt = keys_.find(key);
        if (keyIt != keys_.end()) {
            info.maxRequests = keyIt->second.rateLimit;
        }
        info.windowSeconds = 60;
        info.windowStart = std::chrono::system_clock::now();
        return info;
    }
    return it->second;
}

void ApiAuth::resetRateLimit(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    rateLimits_.erase(key);
}

} // namespace ThreatOne::Api
