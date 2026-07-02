#include <doctest/doctest.h>
#include <api/ApiAuth.h>

#include <thread>
#include <chrono>
#include <string>

using namespace ThreatOne::Api;

TEST_CASE("ApiAuth - Generate API key") {
    ApiAuth auth;
    auto key = auth.generateApiKey("test-key", {"read", "write"}, 100, 365);

    CHECK_FALSE(key.id.empty());
    CHECK_FALSE(key.key.empty());
    CHECK(key.name == "test-key");
    CHECK(key.permissions.size() == 2);
    CHECK(key.rateLimit == 100);
}

TEST_CASE("ApiAuth - Validate valid API key") {
    ApiAuth auth;
    auto key = auth.generateApiKey("valid-key", {"read"});

    CHECK(auth.validateApiKey(key.key));
}

TEST_CASE("ApiAuth - Reject invalid API key") {
    ApiAuth auth;
    auth.generateApiKey("valid-key", {"read"});

    CHECK_FALSE(auth.validateApiKey("invalid-key-that-does-not-exist"));
}

TEST_CASE("ApiAuth - Reject expired API key") {
    ApiAuth auth;
    // Generate a key that expires in 0 days (already expired)
    auto key = auth.generateApiKey("expired-key", {"read"}, 100, 0);

    CHECK_FALSE(auth.validateApiKey(key.key));
}

TEST_CASE("ApiAuth - Revoke API key") {
    ApiAuth auth;
    auto key = auth.generateApiKey("revoke-test", {"read"});

    CHECK(auth.validateApiKey(key.key));
    CHECK(auth.revokeApiKey(key.id));
    CHECK_FALSE(auth.validateApiKey(key.key));
}

TEST_CASE("ApiAuth - Revoke nonexistent key returns false") {
    ApiAuth auth;
    CHECK_FALSE(auth.revokeApiKey("nonexistent-id"));
}

TEST_CASE("ApiAuth - Get API key info") {
    ApiAuth auth;
    auto key = auth.generateApiKey("info-test", {"read", "write", "admin"});

    auto info = auth.getApiKeyInfo(key.key);
    REQUIRE(info.has_value());
    CHECK(info->name == "info-test");
    CHECK(info->permissions.size() == 3);
}

TEST_CASE("ApiAuth - Get info for nonexistent key returns nullopt") {
    ApiAuth auth;
    auto info = auth.getApiKeyInfo("nonexistent");
    CHECK_FALSE(info.has_value());
}

TEST_CASE("ApiAuth - Generate and validate JWT") {
    ApiAuth auth;
    std::string secret = "my-secret-key";

    JwtPayload payload;
    payload.subject = "user-123";
    payload.issuer = "threatone";
    payload.audience = "api";
    payload.issuedAt = std::chrono::system_clock::now();
    payload.expiresAt = std::chrono::system_clock::now() + std::chrono::hours(1);
    payload.claims["role"] = "admin";

    std::string token = auth.generateJwt(payload, secret);
    CHECK_FALSE(token.empty());

    // Token should have 3 parts
    int dotCount = 0;
    for (char c : token) {
        if (c == '.') dotCount++;
    }
    CHECK(dotCount == 2);

    auto result = auth.validateJwt(token, secret);
    CHECK(result.valid);
    CHECK(result.payload.subject == "user-123");
    CHECK(result.payload.issuer == "threatone");
    CHECK(result.payload.audience == "api");
}

TEST_CASE("ApiAuth - Reject JWT with wrong secret") {
    ApiAuth auth;

    JwtPayload payload;
    payload.subject = "user-456";
    payload.issuer = "threatone";
    payload.issuedAt = std::chrono::system_clock::now();
    payload.expiresAt = std::chrono::system_clock::now() + std::chrono::hours(1);

    std::string token = auth.generateJwt(payload, "secret-1");
    auto result = auth.validateJwt(token, "wrong-secret");

    CHECK_FALSE(result.valid);
    CHECK(result.error == "Invalid signature");
}

TEST_CASE("ApiAuth - Reject expired JWT") {
    ApiAuth auth;
    std::string secret = "test-secret";

    JwtPayload payload;
    payload.subject = "user-789";
    payload.issuer = "threatone";
    payload.issuedAt = std::chrono::system_clock::now() - std::chrono::hours(2);
    payload.expiresAt = std::chrono::system_clock::now() - std::chrono::hours(1);

    std::string token = auth.generateJwt(payload, secret);
    auto result = auth.validateJwt(token, secret);

    CHECK_FALSE(result.valid);
    CHECK(result.error == "Token expired");
}

TEST_CASE("ApiAuth - Reject malformed JWT") {
    ApiAuth auth;

    auto result = auth.validateJwt("not.a.valid.token.too.many.parts", "secret");
    CHECK_FALSE(result.valid);

    auto result2 = auth.validateJwt("onlytwoparts.here", "secret");
    CHECK_FALSE(result2.valid);
}

TEST_CASE("ApiAuth - Rate limiting allows requests within limit") {
    ApiAuth auth;
    auto key = auth.generateApiKey("rate-test", {"read"}, 5);

    // Should allow 5 requests
    for (int i = 0; i < 5; ++i) {
        CHECK(auth.checkRateLimit(key.key));
    }
}

TEST_CASE("ApiAuth - Rate limiting blocks excess requests") {
    ApiAuth auth;
    auto key = auth.generateApiKey("rate-block", {"read"}, 3);

    // Use up all requests
    CHECK(auth.checkRateLimit(key.key));
    CHECK(auth.checkRateLimit(key.key));
    CHECK(auth.checkRateLimit(key.key));

    // 4th request should be blocked
    CHECK_FALSE(auth.checkRateLimit(key.key));
}

TEST_CASE("ApiAuth - Rate limit info") {
    ApiAuth auth;
    auto key = auth.generateApiKey("info-rate", {"read"}, 10);

    auth.checkRateLimit(key.key);
    auth.checkRateLimit(key.key);

    auto info = auth.getRateLimitInfo(key.key);
    CHECK(info.maxRequests == 10);
    CHECK(info.currentCount == 2);
    CHECK(info.windowSeconds == 60);
}

TEST_CASE("ApiAuth - Rate limit for invalid key returns false") {
    ApiAuth auth;
    CHECK_FALSE(auth.checkRateLimit("nonexistent-key"));
}

TEST_CASE("ApiAuth - Reset rate limit") {
    ApiAuth auth;
    auto key = auth.generateApiKey("reset-rate", {"read"}, 2);

    CHECK(auth.checkRateLimit(key.key));
    CHECK(auth.checkRateLimit(key.key));
    CHECK_FALSE(auth.checkRateLimit(key.key));

    auth.resetRateLimit(key.key);
    CHECK(auth.checkRateLimit(key.key));
}
