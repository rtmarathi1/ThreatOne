#include "identity/CloudIdentityProvider.h"

#include <algorithm>
#include <chrono>
#include <string>
#include <vector>

namespace ThreatOne::Identity {

// AzureAD Provider Implementation

bool AzureADProvider::initialize(const CloudIdentityConfig& config) {
    if (config.tenantId.empty() || config.clientId.empty() || config.clientSecret.empty()) {
        return false;
    }
    config_ = config;
    initialized_ = true;
    return true;
}

CloudToken AzureADProvider::authenticate(const std::string& authCode) {
    if (!initialized_ || authCode.empty()) {
        return CloudToken{};
    }
    CloudToken token;
    token.token = "azure-token-" + authCode;
    token.refreshToken = "azure-refresh-" + authCode;
    token.expiresAt = std::chrono::system_clock::now() + std::chrono::hours(1);
    token.userId = "azure-user-001";
    token.valid = true;
    return token;
}

CloudToken AzureADProvider::refreshToken(const std::string& refreshToken) {
    if (!initialized_ || refreshToken.empty()) {
        return CloudToken{};
    }
    CloudToken token;
    token.token = "azure-token-refreshed";
    token.refreshToken = "azure-refresh-new";
    token.expiresAt = std::chrono::system_clock::now() + std::chrono::hours(1);
    token.userId = "azure-user-001";
    token.valid = true;
    return token;
}

bool AzureADProvider::provisionUser(const CloudUser& user) {
    if (!initialized_) {
        return false;
    }
    // Check if user already exists
    for (const auto& existing : users_) {
        if (existing.id == user.id) {
            return false;
        }
    }
    users_.push_back(user);
    return true;
}

bool AzureADProvider::deprovisionUser(const std::string& userId) {
    if (!initialized_) {
        return false;
    }
    auto it = std::remove_if(users_.begin(), users_.end(),
        [&userId](const CloudUser& u) { return u.id == userId; });
    if (it == users_.end()) {
        return false;
    }
    users_.erase(it, users_.end());
    return true;
}

std::vector<CloudUser> AzureADProvider::listUsers() {
    if (!initialized_) {
        return {};
    }
    return users_;
}

// Google Workspace Provider Implementation

bool GoogleWorkspaceProvider::initialize(const CloudIdentityConfig& config) {
    if (config.clientId.empty() || config.clientSecret.empty()) {
        return false;
    }
    config_ = config;
    initialized_ = true;
    return true;
}

CloudToken GoogleWorkspaceProvider::authenticate(const std::string& authCode) {
    if (!initialized_ || authCode.empty()) {
        return CloudToken{};
    }
    CloudToken token;
    token.token = "google-token-" + authCode;
    token.refreshToken = "google-refresh-" + authCode;
    token.expiresAt = std::chrono::system_clock::now() + std::chrono::hours(1);
    token.userId = "google-user-001";
    token.valid = true;
    return token;
}

CloudToken GoogleWorkspaceProvider::refreshToken(const std::string& refreshToken) {
    if (!initialized_ || refreshToken.empty()) {
        return CloudToken{};
    }
    CloudToken token;
    token.token = "google-token-refreshed";
    token.refreshToken = "google-refresh-new";
    token.expiresAt = std::chrono::system_clock::now() + std::chrono::hours(1);
    token.userId = "google-user-001";
    token.valid = true;
    return token;
}

bool GoogleWorkspaceProvider::provisionUser(const CloudUser& user) {
    if (!initialized_) {
        return false;
    }
    for (const auto& existing : users_) {
        if (existing.id == user.id) {
            return false;
        }
    }
    users_.push_back(user);
    return true;
}

bool GoogleWorkspaceProvider::deprovisionUser(const std::string& userId) {
    if (!initialized_) {
        return false;
    }
    auto it = std::remove_if(users_.begin(), users_.end(),
        [&userId](const CloudUser& u) { return u.id == userId; });
    if (it == users_.end()) {
        return false;
    }
    users_.erase(it, users_.end());
    return true;
}

std::vector<CloudUser> GoogleWorkspaceProvider::listUsers() {
    if (!initialized_) {
        return {};
    }
    return users_;
}

} // namespace ThreatOne::Identity
