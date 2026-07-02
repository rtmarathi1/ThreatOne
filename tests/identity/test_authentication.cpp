#include <doctest/doctest.h>
#include <identity/AuthenticationManager.h>

#include <thread>
#include <set>
#include <chrono>
#include <cstddef>
#include <string>

using namespace ThreatOne::Identity;

TEST_CASE("Authentication - SHA256 empty string") {
    std::string hash = AuthenticationManager::sha256("");
    CHECK(hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST_CASE("Authentication - SHA256 known test vector") {
    std::string hash = AuthenticationManager::sha256("abc");
    CHECK(hash == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_CASE("Authentication - SHA256 same input same hash") {
    std::string h1 = AuthenticationManager::sha256("test");
    std::string h2 = AuthenticationManager::sha256("test");
    CHECK(h1 == h2);
}

TEST_CASE("Authentication - SHA256 different input different hash") {
    std::string h1 = AuthenticationManager::sha256("test1");
    std::string h2 = AuthenticationManager::sha256("test2");
    CHECK(h1 != h2);
}

TEST_CASE("Authentication - Same password different salts produce different hashes") {
    std::string salt1 = AuthenticationManager::generateSalt();
    std::string salt2 = AuthenticationManager::generateSalt();
    CHECK(salt1 != salt2);

    std::string hash1 = AuthenticationManager::hashPassword("password", salt1);
    std::string hash2 = AuthenticationManager::hashPassword("password", salt2);
    CHECK(hash1 != hash2);
}

TEST_CASE("Authentication - Same password and salt produce same hash") {
    std::string salt = "fixedsalt12345ab";
    std::string hash1 = AuthenticationManager::hashPassword("mypassword", salt);
    std::string hash2 = AuthenticationManager::hashPassword("mypassword", salt);
    CHECK(hash1 == hash2);
}

TEST_CASE("Authentication - Different passwords same salt produce different hashes") {
    std::string salt = "fixedsalt12345ab";
    std::string hash1 = AuthenticationManager::hashPassword("password1", salt);
    std::string hash2 = AuthenticationManager::hashPassword("password2", salt);
    CHECK(hash1 != hash2);
}

TEST_CASE("Authentication - Salt generation produces unique values") {
    std::set<std::string> salts;
    for (int i = 0; i < 10; ++i) {
        salts.insert(AuthenticationManager::generateSalt());
    }
    CHECK(salts.size() == 10);
}

TEST_CASE("Authentication - Register new user") {
    AuthenticationManager auth;
    bool result = auth.registerUser("user-001", "alice", "secretpass");
    CHECK(result);
    CHECK(auth.userExists("alice"));
}

TEST_CASE("Authentication - Cannot register duplicate username") {
    AuthenticationManager auth;
    auth.registerUser("user-001", "alice", "secretpass");
    bool result = auth.registerUser("user-002", "alice", "otherpass");
    CHECK_FALSE(result);
}

TEST_CASE("Authentication - Verify password after registration") {
    AuthenticationManager auth;
    auth.registerUser("user-001", "alice", "secretpass");
    CHECK(auth.verifyPassword("alice", "secretpass"));
    CHECK_FALSE(auth.verifyPassword("alice", "wrongpass"));
}

TEST_CASE("Authentication - Verify nonexistent user fails") {
    AuthenticationManager auth;
    CHECK_FALSE(auth.verifyPassword("ghost", "anything"));
}

TEST_CASE("Authentication - Authenticate creates valid session") {
    AuthenticationManager auth;
    auth.registerUser("user-001", "alice", "secretpass");
    std::string token = auth.authenticate("alice", "secretpass");
    CHECK_FALSE(token.empty());
    CHECK(auth.validateSession(token));
}

TEST_CASE("Authentication - Failed auth returns empty token") {
    AuthenticationManager auth;
    auth.registerUser("user-001", "alice", "secretpass");
    std::string token = auth.authenticate("alice", "wrongpass");
    CHECK(token.empty());
}

TEST_CASE("Authentication - Session info is correct") {
    AuthenticationManager auth;
    auth.registerUser("user-001", "alice", "secretpass");
    std::string token = auth.authenticate("alice", "secretpass");
    auto info = auth.getSessionInfo(token);
    CHECK(info.userId == "user-001");
    CHECK(info.token == token);
}

TEST_CASE("Authentication - Invalidate session") {
    AuthenticationManager auth;
    auth.registerUser("user-001", "alice", "secretpass");
    std::string token = auth.authenticate("alice", "secretpass");
    CHECK(auth.validateSession(token));
    bool invalidated = auth.invalidateSession(token);
    CHECK(invalidated);
    CHECK_FALSE(auth.validateSession(token));
}

TEST_CASE("Authentication - Invalidate nonexistent session returns false") {
    AuthenticationManager auth;
    CHECK_FALSE(auth.invalidateSession("nonexistent-token"));
}

TEST_CASE("Authentication - Tokens are unique") {
    AuthenticationManager auth;
    std::set<std::string> tokens;
    for (int i = 0; i < 20; ++i) {
        tokens.insert(auth.createSession("user-001"));
    }
    CHECK(tokens.size() == 20);
}

TEST_CASE("Authentication - Expired sessions are rejected") {
    AuthenticationManager auth;
    auth.registerUser("user-001", "alice", "secretpass");
    auth.setSessionDuration(std::chrono::seconds(0));
    std::string token = auth.createSession("user-001");
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    CHECK_FALSE(auth.validateSession(token));
}

TEST_CASE("Authentication - Refresh extends session") {
    AuthenticationManager auth;
    auth.setSessionDuration(std::chrono::seconds(3600));
    std::string token = auth.createSession("user-001");
    CHECK(auth.validateSession(token));
    bool refreshed = auth.refreshSession(token);
    CHECK(refreshed);
    CHECK(auth.validateSession(token));
}

TEST_CASE("Authentication - Cannot refresh expired session") {
    AuthenticationManager auth;
    auth.setSessionDuration(std::chrono::seconds(0));
    std::string token = auth.createSession("user-001");
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    CHECK_FALSE(auth.refreshSession(token));
}

TEST_CASE("Authentication - Clean expired sessions") {
    AuthenticationManager auth;
    auth.setSessionDuration(std::chrono::seconds(0));
    auth.createSession("user-001");
    auth.createSession("user-001");
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    std::size_t cleaned = auth.cleanExpiredSessions();
    CHECK(cleaned == 2);
}

TEST_CASE("Authentication - Enable MFA for user") {
    AuthenticationManager auth;
    auth.registerUser("user-001", "alice", "secretpass");
    bool enabled = auth.enableMFA("user-001", "JBSWY3DPEHPK3PXP");
    CHECK(enabled);
}

TEST_CASE("Authentication - Verify MFA with valid code") {
    AuthenticationManager auth;
    auth.registerUser("user-001", "alice", "secretpass");
    std::string token = auth.authenticate("alice", "secretpass");
    bool verified = auth.verifyMFA(token, "123456");
    CHECK(verified);
    auto info = auth.getSessionInfo(token);
    CHECK(info.mfaVerified);
}

TEST_CASE("Authentication - Invalid MFA code length rejected") {
    AuthenticationManager auth;
    auth.registerUser("user-001", "alice", "secretpass");
    std::string token = auth.authenticate("alice", "secretpass");
    bool verified = auth.verifyMFA(token, "12345"); // 5 digits - invalid
    CHECK_FALSE(verified);
}

TEST_CASE("Authentication - Change password with correct old password") {
    AuthenticationManager auth;
    auth.registerUser("user-001", "alice", "oldpass");
    bool changed = auth.changePassword("user-001", "oldpass", "newpass");
    CHECK(changed);
    CHECK(auth.verifyPassword("alice", "newpass"));
    CHECK_FALSE(auth.verifyPassword("alice", "oldpass"));
}

TEST_CASE("Authentication - Cannot change with wrong old password") {
    AuthenticationManager auth;
    auth.registerUser("user-001", "alice", "oldpass");
    bool changed = auth.changePassword("user-001", "wrongold", "newpass");
    CHECK_FALSE(changed);
    CHECK(auth.verifyPassword("alice", "oldpass"));
}
