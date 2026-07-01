#pragma once

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <optional>
#include <mutex>
#include <unordered_map>

namespace ThreatOne::Api {

struct ApiKey {
    std::string id;
    std::string key;
    std::string name;
    std::vector<std::string> permissions;
    int rateLimit = 100; // requests per window
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point expiresAt;
};

struct JwtPayload {
    std::string subject;
    std::string issuer;
    std::string audience;
    std::chrono::system_clock::time_point issuedAt;
    std::chrono::system_clock::time_point expiresAt;
    std::map<std::string, std::string> claims;
};

struct RateLimitInfo {
    int maxRequests = 100;
    int windowSeconds = 60;
    int currentCount = 0;
    std::chrono::system_clock::time_point windowStart;
};

struct JwtValidationResult {
    bool valid = false;
    std::string error;
    JwtPayload payload;
};

class IApiAuth {
public:
    virtual ~IApiAuth() = default;

    virtual ApiKey generateApiKey(const std::string& name, const std::vector<std::string>& permissions,
                                  int rateLimit = 100, int validDays = 365) = 0;
    virtual bool validateApiKey(const std::string& key) const = 0;
    virtual bool revokeApiKey(const std::string& keyId) = 0;
    virtual std::optional<ApiKey> getApiKeyInfo(const std::string& key) const = 0;

    virtual std::string generateJwt(const JwtPayload& payload, const std::string& secret) = 0;
    virtual JwtValidationResult validateJwt(const std::string& token, const std::string& secret) const = 0;

    virtual bool checkRateLimit(const std::string& key) = 0;
    virtual RateLimitInfo getRateLimitInfo(const std::string& key) const = 0;
    virtual void resetRateLimit(const std::string& key) = 0;
};

class ApiAuth : public IApiAuth {
public:
    ApiAuth();

    ApiKey generateApiKey(const std::string& name, const std::vector<std::string>& permissions,
                          int rateLimit = 100, int validDays = 365) override;
    bool validateApiKey(const std::string& key) const override;
    bool revokeApiKey(const std::string& keyId) override;
    std::optional<ApiKey> getApiKeyInfo(const std::string& key) const override;

    std::string generateJwt(const JwtPayload& payload, const std::string& secret) override;
    JwtValidationResult validateJwt(const std::string& token, const std::string& secret) const override;

    bool checkRateLimit(const std::string& key) override;
    RateLimitInfo getRateLimitInfo(const std::string& key) const override;
    void resetRateLimit(const std::string& key) override;

private:
    std::string generateRandomKey() const;
    std::string generateId() const;
    std::string base64Encode(const std::string& input) const;
    std::string base64Decode(const std::string& input) const;
    std::string computeSignature(const std::string& data, const std::string& secret) const;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, ApiKey> keys_;          // key string -> ApiKey
    std::unordered_map<std::string, std::string> idToKey_;  // id -> key string
    mutable std::unordered_map<std::string, RateLimitInfo> rateLimits_;
};

} // namespace ThreatOne::Api
