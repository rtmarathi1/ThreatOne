#include <doctest/doctest.h>
#include <updates/UpdateManager.h>

using namespace ThreatOne::Updates;

TEST_CASE("UpdateVerifier - Verify matching checksum") {
    UpdateManager mgr;
    auto& uv = mgr.getUpdateVerifier();

    auto result = uv.verifyChecksum("2.0.0", "abc123", "abc123");
    CHECK(result.checksumValid == true);
    CHECK(result.status == VerificationStatus::Verified);
}

TEST_CASE("UpdateVerifier - Verify mismatched checksum") {
    UpdateManager mgr;
    auto& uv = mgr.getUpdateVerifier();

    auto result = uv.verifyChecksum("2.0.0", "abc123", "xyz789");
    CHECK(result.checksumValid == false);
    CHECK(result.status == VerificationStatus::Failed);
}

TEST_CASE("UpdateVerifier - Register and verify signature") {
    UpdateManager mgr;
    auto& uv = mgr.getUpdateVerifier();

    SignatureInfo sig;
    sig.version = "2.0.0";
    sig.algorithm = "SHA256";
    sig.publicKey = "pub_key_data";
    sig.signature = "sig_data";
    CHECK(uv.registerSignature(sig));

    CHECK(uv.verifySignature("2.0.0"));
    CHECK_FALSE(uv.verifySignature("3.0.0"));
}

TEST_CASE("UpdateVerifier - Trusted versions") {
    UpdateManager mgr;
    auto& uv = mgr.getUpdateVerifier();

    CHECK_FALSE(uv.isTrustedUpdate("2.0.0"));
    uv.markAsTrusted("2.0.0");
    CHECK(uv.isTrustedUpdate("2.0.0"));
}

TEST_CASE("UpdateVerifier - Revoke version") {
    UpdateManager mgr;
    auto& uv = mgr.getUpdateVerifier();

    uv.markAsTrusted("2.0.0");
    uv.revokeVersion("2.0.0");
    CHECK_FALSE(uv.isTrustedUpdate("2.0.0"));

    auto revoked = uv.getRevokedVersions();
    CHECK(revoked.size() == 1);
}

TEST_CASE("UpdateVerifier - Verify revoked version fails") {
    UpdateManager mgr;
    auto& uv = mgr.getUpdateVerifier();

    uv.revokeVersion("2.0.0");
    auto result = uv.verify("2.0.0");
    CHECK(result.status == VerificationStatus::Failed);
}

TEST_CASE("UpdateVerifier - Statistics") {
    UpdateManager mgr;
    auto& uv = mgr.getUpdateVerifier();

    uv.verifyChecksum("1.0.0", "a", "a");
    uv.verifyChecksum("2.0.0", "a", "b");

    CHECK(uv.getTotalVerifications() == 2);
    CHECK(uv.getFailedVerifications() == 1);
}
