#include <doctest/doctest.h>
#include <licensing/LicenseValidator.h>
#include <string>

using namespace ThreatOne::Licensing;

// Helper: generate a valid key for testing by computing the correct checksum
static std::string generateValidKey(const std::string& tier, const std::string& seg1,
                                     const std::string& seg2, const std::string& seg3) {
    // Replicate the djb2 checksum algorithm
    std::string combined = tier + seg1 + seg2 + seg3;
    unsigned long hash = 5381;
    for (char c : combined) {
        hash = ((hash << 5) + hash) + static_cast<unsigned char>(c);
    }
    const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string checksum;
    checksum.reserve(5);
    for (int i = 0; i < 5; ++i) {
        checksum += chars[hash % 36];
        hash /= 36;
    }
    return tier + "-" + seg1 + "-" + seg2 + "-" + seg3 + "-" + checksum;
}

TEST_CASE("LicenseValidator - Parse valid Free key") {
    LicenseValidator validator;
    std::string key = generateValidKey("FREE", "ABCDE", "12345", "FGHIJ");
    auto parsed = validator.parseKey(key);
    REQUIRE(parsed.has_value());
    CHECK(parsed->tier == LicenseType::Free);
    CHECK(parsed->segment1 == "ABCDE");
    CHECK(parsed->segment2 == "12345");
    CHECK(parsed->segment3 == "FGHIJ");
}

TEST_CASE("LicenseValidator - Parse valid Pro key") {
    LicenseValidator validator;
    std::string key = generateValidKey("PRO", "ZZZZZ", "AAAAA", "99999");
    auto parsed = validator.parseKey(key);
    REQUIRE(parsed.has_value());
    CHECK(parsed->tier == LicenseType::Professional);
}

TEST_CASE("LicenseValidator - Parse valid Enterprise key") {
    LicenseValidator validator;
    std::string key = generateValidKey("ENT", "HELLO", "WORLD", "TEST1");
    auto parsed = validator.parseKey(key);
    REQUIRE(parsed.has_value());
    CHECK(parsed->tier == LicenseType::Enterprise);
}

TEST_CASE("LicenseValidator - Parse valid Ultimate key") {
    LicenseValidator validator;
    std::string key = generateValidKey("ULT", "ULTRA", "POWER", "KEYS0");
    auto parsed = validator.parseKey(key);
    REQUIRE(parsed.has_value());
    CHECK(parsed->tier == LicenseType::Ultimate);
}

TEST_CASE("LicenseValidator - Reject empty key") {
    LicenseValidator validator;
    auto parsed = validator.parseKey("");
    CHECK_FALSE(parsed.has_value());
}

TEST_CASE("LicenseValidator - Reject key with wrong number of segments") {
    LicenseValidator validator;
    auto parsed = validator.parseKey("FREE-ABCDE-12345");
    CHECK_FALSE(parsed.has_value());
}

TEST_CASE("LicenseValidator - Reject key with invalid tier") {
    LicenseValidator validator;
    auto parsed = validator.parseKey("GOLD-ABCDE-12345-FGHIJ-CHECK");
    CHECK_FALSE(parsed.has_value());
}

TEST_CASE("LicenseValidator - Reject key with wrong segment length") {
    LicenseValidator validator;
    auto parsed = validator.parseKey("FREE-ABC-12345-FGHIJ-CHECK");
    CHECK_FALSE(parsed.has_value());
}

TEST_CASE("LicenseValidator - Reject key with lowercase characters") {
    LicenseValidator validator;
    auto parsed = validator.parseKey("FREE-abcde-12345-FGHIJ-CHECK");
    CHECK_FALSE(parsed.has_value());
}

TEST_CASE("LicenseValidator - Validate correct checksum") {
    LicenseValidator validator;
    std::string key = generateValidKey("FREE", "ABCDE", "12345", "FGHIJ");
    auto parsed = validator.parseKey(key);
    REQUIRE(parsed.has_value());
    CHECK(validator.validateChecksum(parsed.value()));
}

TEST_CASE("LicenseValidator - Reject incorrect checksum") {
    LicenseValidator validator;
    // Manually create a key with wrong checksum
    auto parsed = validator.parseKey("FREE-ABCDE-12345-FGHIJ-ZZZZZ");
    REQUIRE(parsed.has_value());
    CHECK_FALSE(validator.validateChecksum(parsed.value()));
}

TEST_CASE("LicenseValidator - Checksum differs for different tiers") {
    LicenseValidator validator;
    std::string freeKey = generateValidKey("FREE", "ABCDE", "12345", "FGHIJ");
    std::string proKey = generateValidKey("PRO", "ABCDE", "12345", "FGHIJ");

    auto freeParsed = validator.parseKey(freeKey);
    auto proParsed = validator.parseKey(proKey);
    REQUIRE(freeParsed.has_value());
    REQUIRE(proParsed.has_value());

    // Different tiers should produce different checksums
    CHECK(freeParsed->checksum != proParsed->checksum);
}

TEST_CASE("LicenseValidator - Check expiration with future date") {
    LicenseValidator validator;
    // Use a far future date
    CHECK_FALSE(validator.checkExpiration("2099-12-31"));
}

TEST_CASE("LicenseValidator - Check expiration with past date") {
    LicenseValidator validator;
    CHECK(validator.checkExpiration("2020-01-01"));
}

TEST_CASE("LicenseValidator - Check expiration with empty string") {
    LicenseValidator validator;
    // Empty = no expiration = not expired
    CHECK_FALSE(validator.checkExpiration(""));
}

TEST_CASE("LicenseValidator - Check expiration with invalid format") {
    LicenseValidator validator;
    CHECK(validator.checkExpiration("not-a-date"));
}

TEST_CASE("LicenseValidator - Seat limit for Free tier") {
    LicenseValidator validator;
    CHECK(validator.getSeatLimit(LicenseType::Free) == 1);
}

TEST_CASE("LicenseValidator - Seat limit for Professional tier") {
    LicenseValidator validator;
    CHECK(validator.getSeatLimit(LicenseType::Professional) == 25);
}

TEST_CASE("LicenseValidator - Seat limit for Enterprise tier") {
    LicenseValidator validator;
    CHECK(validator.getSeatLimit(LicenseType::Enterprise) == 500);
}

TEST_CASE("LicenseValidator - Seat limit for Ultimate tier") {
    LicenseValidator validator;
    CHECK(validator.getSeatLimit(LicenseType::Ultimate) == 10000);
}

TEST_CASE("LicenseValidator - Enforce seat limit within bounds") {
    LicenseValidator validator;
    CHECK(validator.enforceSeatLimit(LicenseType::Professional, 10));
    CHECK(validator.enforceSeatLimit(LicenseType::Professional, 25));
}

TEST_CASE("LicenseValidator - Enforce seat limit exceeds bounds") {
    LicenseValidator validator;
    CHECK_FALSE(validator.enforceSeatLimit(LicenseType::Free, 2));
    CHECK_FALSE(validator.enforceSeatLimit(LicenseType::Professional, 26));
}

TEST_CASE("LicenseValidator - Grace period for Free is zero") {
    LicenseValidator validator;
    CHECK(validator.calculateGracePeriod(LicenseType::Free) == 0);
}

TEST_CASE("LicenseValidator - Grace period for Professional is 7 days") {
    LicenseValidator validator;
    CHECK(validator.calculateGracePeriod(LicenseType::Professional) == 7);
}

TEST_CASE("LicenseValidator - Grace period for Enterprise is 30 days") {
    LicenseValidator validator;
    CHECK(validator.calculateGracePeriod(LicenseType::Enterprise) == 30);
}

TEST_CASE("LicenseValidator - Grace period for Ultimate is 60 days") {
    LicenseValidator validator;
    CHECK(validator.calculateGracePeriod(LicenseType::Ultimate) == 60);
}

TEST_CASE("LicenseValidator - Full validation rejects malformed key") {
    LicenseValidator validator;
    auto result = validator.validate("not-a-valid-key");
    CHECK_FALSE(result.valid);
    CHECK(result.reason == "Invalid key format");
}

TEST_CASE("LicenseValidator - Full validation rejects bad checksum") {
    LicenseValidator validator;
    auto result = validator.validate("FREE-ABCDE-12345-FGHIJ-ZZZZZ");
    CHECK_FALSE(result.valid);
    CHECK(result.reason == "Invalid checksum");
}

TEST_CASE("LicenseValidator - Full validation returns seats and grace period") {
    LicenseValidator validator;
    std::string key = generateValidKey("ENT", "HELLO", "WORLD", "TEST1");
    auto result = validator.validate(key);
    // Whether valid depends on expiration date from segments, but we can check seats and grace
    CHECK(result.seatsAllowed == 500);
    CHECK(result.gracePeriodDays == 30);
}
