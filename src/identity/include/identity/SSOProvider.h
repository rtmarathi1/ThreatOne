#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>

namespace ThreatOne::Identity {

struct SSOClaims {
    std::string subject;
    std::string email;
    std::string name;
    std::vector<std::string> groups;
    std::string issuer;
    std::unordered_map<std::string, std::string> additionalClaims;
};

struct SSOToken {
    std::string accessToken;
    std::string refreshToken;
    std::string tokenType = "Bearer";
    std::chrono::system_clock::time_point expiresAt;
    SSOClaims claims;
    bool valid = false;
};

struct SSOProviderConfig {
    std::string name;
    std::string issuerUrl;
    std::string clientId;
    std::string clientSecret;
    std::string redirectUri;
    std::vector<std::string> scopes;
    std::string metadataUrl;
    bool enabled = true;
};

enum class SSOProtocol {
    SAML2,
    OAuth2,
    OIDC
};

class ISSOProvider {
public:
    virtual ~ISSOProvider() = default;

    virtual bool initialize(const SSOProviderConfig& config) = 0;
    virtual SSOToken authenticate(const std::string& authCode) = 0;
    virtual SSOToken refreshToken(const std::string& refreshToken) = 0;
    virtual bool validateToken(const std::string& token) = 0;
    virtual SSOClaims parseClaims(const std::string& token) = 0;
    virtual std::string getAuthorizationUrl(const std::string& state) = 0;
    virtual SSOProtocol getProtocol() const = 0;
    virtual std::string getProviderName() const = 0;
};

class SAMLProvider : public ISSOProvider {
public:
    SAMLProvider() = default;
    ~SAMLProvider() override = default;

    bool initialize(const SSOProviderConfig& config) override;
    SSOToken authenticate(const std::string& authCode) override;
    SSOToken refreshToken(const std::string& refreshToken) override;
    bool validateToken(const std::string& token) override;
    SSOClaims parseClaims(const std::string& token) override;
    std::string getAuthorizationUrl(const std::string& state) override;
    SSOProtocol getProtocol() const override { return SSOProtocol::SAML2; }
    std::string getProviderName() const override { return "SAML2"; }

private:
    SSOProviderConfig config_;
    bool initialized_ = false;
};

class OAuthProvider : public ISSOProvider {
public:
    OAuthProvider() = default;
    ~OAuthProvider() override = default;

    bool initialize(const SSOProviderConfig& config) override;
    SSOToken authenticate(const std::string& authCode) override;
    SSOToken refreshToken(const std::string& refreshToken) override;
    bool validateToken(const std::string& token) override;
    SSOClaims parseClaims(const std::string& token) override;
    std::string getAuthorizationUrl(const std::string& state) override;
    SSOProtocol getProtocol() const override { return SSOProtocol::OIDC; }
    std::string getProviderName() const override { return "OAuth2/OIDC"; }

private:
    SSOProviderConfig config_;
    bool initialized_ = false;
};

} // namespace ThreatOne::Identity
