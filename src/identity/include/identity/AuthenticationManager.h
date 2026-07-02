#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <cstdint>
#include <cstddef>

namespace ThreatOne::Identity {

struct SessionInfo {
    std::string token;
    std::string userId;
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point expiresAt;
    bool mfaVerified = false;
    std::string sourceIP;
};

struct StoredCredential {
    std::string userId;
    std::string username;
    std::string passwordHash;
    std::string salt;
    bool mfaEnabled = false;
    std::string mfaSecret;
};

class AuthenticationManager {
public:
    AuthenticationManager();
    ~AuthenticationManager() = default;

    // User credential management
    bool registerUser(const std::string& userId, const std::string& username, const std::string& password);
    bool changePassword(const std::string& userId, const std::string& oldPassword, const std::string& newPassword);
    bool userExists(const std::string& username) const;

    // Authentication
    std::string authenticate(const std::string& username, const std::string& password);
    bool verifyPassword(const std::string& username, const std::string& password) const;

    // Session management
    std::string createSession(const std::string& userId, const std::string& sourceIP = "");
    bool validateSession(const std::string& token) const;
    bool invalidateSession(const std::string& token);
    bool refreshSession(const std::string& token);
    SessionInfo getSessionInfo(const std::string& token) const;

    // MFA interface
    bool enableMFA(const std::string& userId, const std::string& secret);
    bool verifyMFA(const std::string& token, const std::string& code);

    // Session configuration
    void setSessionDuration(std::chrono::seconds duration);
    std::chrono::seconds getSessionDuration() const;

    // Cleanup expired sessions
    std::size_t cleanExpiredSessions();

    // SHA256 hashing utility
    static std::string sha256(const std::string& input);
    static std::string generateSalt(std::size_t length = 16);
    static std::string hashPassword(const std::string& password, const std::string& salt);
    static std::string generateToken();

private:
    std::unordered_map<std::string, StoredCredential> credentials_; // username -> credential
    std::unordered_map<std::string, SessionInfo> sessions_; // token -> session
    std::chrono::seconds sessionDuration_{3600}; // default 1 hour
    uint64_t tokenCounter_{0};
};

} // namespace ThreatOne::Identity
