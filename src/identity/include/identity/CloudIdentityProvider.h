#pragma once

#include <string>
#include <vector>
#include <chrono>

namespace ThreatOne::Identity {

struct CloudIdentityConfig {
    std::string tenantId;
    std::string clientId;
    std::string clientSecret;
    std::string authority;
    std::vector<std::string> scopes;
    std::string redirectUri;
    bool autoProvision = false;
};

struct CloudToken {
    std::string token;
    std::string refreshToken;
    std::chrono::system_clock::time_point expiresAt;
    std::string userId;
    bool valid = false;
};

struct CloudUser {
    std::string id;
    std::string email;
    std::string displayName;
    std::vector<std::string> groups;
    bool active = true;
};

class ICloudIdentityProvider {
public:
    virtual ~ICloudIdentityProvider() = default;

    virtual bool initialize(const CloudIdentityConfig& config) = 0;
    virtual CloudToken authenticate(const std::string& authCode) = 0;
    virtual CloudToken refreshToken(const std::string& refreshToken) = 0;
    virtual bool provisionUser(const CloudUser& user) = 0;
    virtual bool deprovisionUser(const std::string& userId) = 0;
    virtual std::vector<CloudUser> listUsers() = 0;
    virtual std::string getProviderName() const = 0;
    virtual bool isInitialized() const = 0;
};

class AzureADProvider : public ICloudIdentityProvider {
public:
    AzureADProvider() = default;
    ~AzureADProvider() override = default;

    bool initialize(const CloudIdentityConfig& config) override;
    CloudToken authenticate(const std::string& authCode) override;
    CloudToken refreshToken(const std::string& refreshToken) override;
    bool provisionUser(const CloudUser& user) override;
    bool deprovisionUser(const std::string& userId) override;
    std::vector<CloudUser> listUsers() override;
    std::string getProviderName() const override { return "AzureAD"; }
    bool isInitialized() const override { return initialized_; }

private:
    CloudIdentityConfig config_;
    bool initialized_ = false;
    std::vector<CloudUser> users_;
};

class GoogleWorkspaceProvider : public ICloudIdentityProvider {
public:
    GoogleWorkspaceProvider() = default;
    ~GoogleWorkspaceProvider() override = default;

    bool initialize(const CloudIdentityConfig& config) override;
    CloudToken authenticate(const std::string& authCode) override;
    CloudToken refreshToken(const std::string& refreshToken) override;
    bool provisionUser(const CloudUser& user) override;
    bool deprovisionUser(const std::string& userId) override;
    std::vector<CloudUser> listUsers() override;
    std::string getProviderName() const override { return "GoogleWorkspace"; }
    bool isInitialized() const override { return initialized_; }

private:
    CloudIdentityConfig config_;
    bool initialized_ = false;
    std::vector<CloudUser> users_;
};

} // namespace ThreatOne::Identity
