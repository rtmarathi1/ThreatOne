#include <doctest/doctest.h>
#include <identity/SSOProvider.h>

using namespace ThreatOne::Identity;

TEST_CASE("SSO SAML - Initialize with valid config") {
    SAMLProvider saml;
    SSOProviderConfig config;
    config.name = "Corporate SAML";
    config.issuerUrl = "https://idp.corp.local";
    config.clientId = "sp-entity-id";
    config.redirectUri = "https://app.local/callback";
    CHECK(saml.initialize(config));
    CHECK(saml.getProtocol() == SSOProtocol::SAML2);
    CHECK(saml.getProviderName() == "SAML2");
}

TEST_CASE("SSO SAML - Initialize with empty config fails") {
    SAMLProvider saml;
    SSOProviderConfig emptyConfig;
    CHECK_FALSE(saml.initialize(emptyConfig));
}

TEST_CASE("SSO SAML - Authenticate returns valid token") {
    SAMLProvider saml;
    SSOProviderConfig config;
    config.issuerUrl = "https://idp.corp.local";
    config.clientId = "sp-entity-id";
    saml.initialize(config);
    auto token = saml.authenticate("saml-assertion-123");
    CHECK(token.valid);
    CHECK_FALSE(token.accessToken.empty());
    CHECK(token.claims.issuer == config.issuerUrl);
}

TEST_CASE("SSO SAML - Authenticate with empty code fails") {
    SAMLProvider saml;
    SSOProviderConfig config;
    config.issuerUrl = "https://idp.corp.local";
    config.clientId = "sp-entity-id";
    saml.initialize(config);
    auto token = saml.authenticate("");
    CHECK_FALSE(token.valid);
}

TEST_CASE("SSO SAML - Validate token") {
    SAMLProvider saml;
    SSOProviderConfig config;
    config.issuerUrl = "https://idp.corp.local";
    config.clientId = "sp-entity-id";
    saml.initialize(config);
    auto token = saml.authenticate("assertion-abc");
    CHECK(saml.validateToken(token.accessToken));
    CHECK_FALSE(saml.validateToken("invalid-token"));
}

TEST_CASE("SSO SAML - Parse claims") {
    SAMLProvider saml;
    SSOProviderConfig config;
    config.issuerUrl = "https://idp.corp.local";
    config.clientId = "sp-entity-id";
    saml.initialize(config);
    auto token = saml.authenticate("assertion-xyz");
    auto claims = saml.parseClaims(token.accessToken);
    CHECK_FALSE(claims.email.empty());
    CHECK(claims.issuer == config.issuerUrl);
}

TEST_CASE("SSO SAML - Get authorization URL") {
    SAMLProvider saml;
    SSOProviderConfig config;
    config.issuerUrl = "https://idp.corp.local";
    config.clientId = "sp-entity-id";
    config.redirectUri = "https://app.local/callback";
    saml.initialize(config);
    auto url = saml.getAuthorizationUrl("state123");
    CHECK_FALSE(url.empty());
    CHECK(url.find(config.issuerUrl) != std::string::npos);
}

TEST_CASE("SSO SAML - Does not support refresh") {
    SAMLProvider saml;
    SSOProviderConfig config;
    config.issuerUrl = "https://idp.corp.local";
    config.clientId = "sp-entity-id";
    saml.initialize(config);
    auto token = saml.refreshToken("some-refresh");
    CHECK_FALSE(token.valid);
}

TEST_CASE("SSO OAuth - Initialize with valid config") {
    OAuthProvider oauth;
    SSOProviderConfig config;
    config.issuerUrl = "https://auth.corp.local";
    config.clientId = "client-id-123";
    config.clientSecret = "client-secret-456";
    config.redirectUri = "https://app.local/oauth/callback";
    config.scopes = {"openid", "profile", "email"};
    CHECK(oauth.initialize(config));
    CHECK(oauth.getProtocol() == SSOProtocol::OIDC);
}

TEST_CASE("SSO OAuth - Initialize without secret fails") {
    OAuthProvider oauth;
    SSOProviderConfig badConfig;
    badConfig.issuerUrl = "https://auth.local";
    badConfig.clientId = "client";
    CHECK_FALSE(oauth.initialize(badConfig));
}

TEST_CASE("SSO OAuth - Authenticate returns tokens") {
    OAuthProvider oauth;
    SSOProviderConfig config;
    config.issuerUrl = "https://auth.corp.local";
    config.clientId = "client-id-123";
    config.clientSecret = "client-secret-456";
    oauth.initialize(config);
    auto token = oauth.authenticate("auth-code-xyz");
    CHECK(token.valid);
    CHECK_FALSE(token.accessToken.empty());
    CHECK_FALSE(token.refreshToken.empty());
    CHECK(token.tokenType == "Bearer");
}

TEST_CASE("SSO OAuth - Refresh token works") {
    OAuthProvider oauth;
    SSOProviderConfig config;
    config.issuerUrl = "https://auth.corp.local";
    config.clientId = "client-id-123";
    config.clientSecret = "client-secret-456";
    oauth.initialize(config);
    auto token = oauth.refreshToken("refresh-token-abc");
    CHECK(token.valid);
    CHECK_FALSE(token.accessToken.empty());
}

TEST_CASE("SSO OAuth - Validate token") {
    OAuthProvider oauth;
    SSOProviderConfig config;
    config.issuerUrl = "https://auth.corp.local";
    config.clientId = "client-id-123";
    config.clientSecret = "client-secret-456";
    oauth.initialize(config);
    auto token = oauth.authenticate("code-123");
    CHECK(oauth.validateToken(token.accessToken));
    CHECK_FALSE(oauth.validateToken("random-invalid"));
}

TEST_CASE("SSO OAuth - Parse claims") {
    OAuthProvider oauth;
    SSOProviderConfig config;
    config.issuerUrl = "https://auth.corp.local";
    config.clientId = "client-id-123";
    config.clientSecret = "client-secret-456";
    oauth.initialize(config);
    auto token = oauth.authenticate("code-456");
    auto claims = oauth.parseClaims(token.accessToken);
    CHECK_FALSE(claims.subject.empty());
    CHECK_FALSE(claims.email.empty());
    CHECK(claims.groups.size() > 0);
}

TEST_CASE("SSO OAuth - Authorization URL contains expected params") {
    OAuthProvider oauth;
    SSOProviderConfig config;
    config.issuerUrl = "https://auth.corp.local";
    config.clientId = "client-id-123";
    config.clientSecret = "client-secret-456";
    config.redirectUri = "https://app.local/oauth/callback";
    config.scopes = {"openid", "profile", "email"};
    oauth.initialize(config);
    auto url = oauth.getAuthorizationUrl("random-state");
    CHECK(url.find("client_id=" + config.clientId) != std::string::npos);
    CHECK(url.find("state=random-state") != std::string::npos);
    CHECK(url.find("openid") != std::string::npos);
}

TEST_CASE("SSO - Data model defaults") {
    SSOClaims claims;
    CHECK(claims.subject.empty());
    CHECK(claims.email.empty());
    CHECK(claims.groups.empty());

    SSOToken token;
    CHECK_FALSE(token.valid);
    CHECK(token.accessToken.empty());

    SSOProviderConfig config;
    CHECK(config.enabled);
    CHECK(config.scopes.empty());
}
