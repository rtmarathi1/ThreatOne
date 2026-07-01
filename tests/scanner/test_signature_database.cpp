#include <doctest/doctest.h>
#include <scanner/SignatureDatabase.h>

#include <filesystem>
#include <fstream>

using namespace ThreatOne::Scanner;

TEST_CASE("SignatureDatabase CRUD operations") {
    SUBCASE("Add and retrieve signature") {
        SignatureDatabase db;
        Signature sig;
        sig.name = "TestMalware";
        sig.hash = "abcdef1234567890";
        sig.threatLevel = ThreatLevel::High;
        sig.category = "trojan";
        sig.description = "A test threat";
        sig.dateAdded = "2024-01-01";

        auto addResult = db.addSignature(sig);
        REQUIRE(addResult.isOk());
        CHECK(db.size() == 1);
    }

    SUBCASE("Remove signature") {
        SignatureDatabase db;
        Signature sig;
        sig.name = "Malware1";
        sig.hash = "hash1";
        sig.threatLevel = ThreatLevel::Low;

        db.addSignature(sig);
        CHECK(db.size() == 1);

        // The auto-assigned id is 1
        auto removeResult = db.removeSignature(1);
        REQUIRE(removeResult.isOk());
        CHECK(db.size() == 0);
    }

    SUBCASE("Remove non-existent signature fails") {
        SignatureDatabase db;
        auto result = db.removeSignature(999);
        CHECK(result.isErr());
    }

    SUBCASE("Update signature") {
        SignatureDatabase db;
        Signature sig;
        sig.name = "OriginalName";
        sig.hash = "originalhash";
        sig.threatLevel = ThreatLevel::Low;

        db.addSignature(sig);

        auto getResult = db.getSignature(1);
        REQUIRE(getResult.isOk());

        Signature updated = getResult.value();
        updated.name = "UpdatedName";
        updated.hash = "updatedhash";
        updated.threatLevel = ThreatLevel::Critical;

        auto updateResult = db.updateSignature(updated);
        REQUIRE(updateResult.isOk());

        auto verify = db.getSignature(1);
        REQUIRE(verify.isOk());
        CHECK(verify.value().name == "UpdatedName");
        CHECK(verify.value().hash == "updatedhash");
        CHECK(verify.value().threatLevel == ThreatLevel::Critical);
    }
}

TEST_CASE("SignatureDatabase hash lookup") {
    SUBCASE("Lookup existing hash") {
        SignatureDatabase db;
        Signature sig1;
        sig1.name = "Virus1";
        sig1.hash = "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222";
        sig1.threatLevel = ThreatLevel::High;
        sig1.category = "virus";
        db.addSignature(sig1);

        auto result = db.lookupByHash("aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222");
        REQUIRE(result.has_value());
        CHECK(result->name == "Virus1");
        CHECK(result->threatLevel == ThreatLevel::High);
    }

    SUBCASE("Lookup non-existent hash") {
        SignatureDatabase db;
        auto result = db.lookupByHash("0000000000000000000000000000000000000000000000000000000000000000");
        CHECK_FALSE(result.has_value());
    }

    SUBCASE("Hash index updates on update") {
        SignatureDatabase db;
        Signature sig1;
        sig1.name = "Virus1";
        sig1.hash = "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222";
        sig1.threatLevel = ThreatLevel::High;
        db.addSignature(sig1);

        auto getResult = db.getSignature(1);
        REQUIRE(getResult.isOk());
        Signature updated = getResult.value();
        updated.hash = "newhash1234";
        db.updateSignature(updated);

        // Old hash should not resolve
        auto oldResult = db.lookupByHash("aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222");
        CHECK_FALSE(oldResult.has_value());

        // New hash should resolve
        auto newResult = db.lookupByHash("newhash1234");
        REQUIRE(newResult.has_value());
        CHECK(newResult->name == "Virus1");
    }
}

TEST_CASE("SignatureDatabase JSON loading") {
    SignatureDatabase db;

    SUBCASE("Load from valid JSON string") {
        std::string json = R"({
            "signatures": [
                {
                    "name": "TestVirus",
                    "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "threat_level": "critical",
                    "category": "virus",
                    "description": "Empty file signature",
                    "date_added": "2024-01-15"
                },
                {
                    "name": "TestTrojan",
                    "hash": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                    "threat_level": "high",
                    "category": "trojan",
                    "description": "ABC signature",
                    "date_added": "2024-02-01"
                }
            ]
        })";

        auto result = db.loadFromJsonString(json);
        REQUIRE(result.isOk());
        CHECK(result.value() == 2);
        CHECK(db.size() == 2);

        auto lookup = db.lookupByHash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        REQUIRE(lookup.has_value());
        CHECK(lookup->name == "TestVirus");
        CHECK(lookup->threatLevel == ThreatLevel::Critical);
    }

    SUBCASE("Load from invalid JSON string") {
        auto result = db.loadFromJsonString("not valid json");
        CHECK(result.isErr());
    }

    SUBCASE("Load from missing signatures array") {
        auto result = db.loadFromJsonString(R"({"data": []})");
        CHECK(result.isErr());
    }

    SUBCASE("Load from JSON file") {
        auto tempDir = std::filesystem::temp_directory_path() / "threatone_test_sigdb";
        std::filesystem::create_directories(tempDir);

        auto sigFile = tempDir / "signatures.json";
        {
            std::ofstream f(sigFile);
            f << R"({
                "signatures": [
                    {
                        "name": "FileSig",
                        "hash": "1234567890abcdef",
                        "threat_level": "medium",
                        "category": "adware"
                    }
                ]
            })";
        }

        auto result = db.loadFromJson(sigFile);
        REQUIRE(result.isOk());
        CHECK(result.value() == 1);

        std::filesystem::remove_all(tempDir);
    }
}

TEST_CASE("SignatureDatabase clear and size") {
    SignatureDatabase db;

    Signature sig;
    sig.name = "test";
    sig.hash = "testhash";
    db.addSignature(sig);

    CHECK(db.size() == 1);
    db.clear();
    CHECK(db.size() == 0);
}

TEST_CASE("SignatureDatabase threat level conversion") {
    CHECK(threatLevelToString(ThreatLevel::Low) == "low");
    CHECK(threatLevelToString(ThreatLevel::Medium) == "medium");
    CHECK(threatLevelToString(ThreatLevel::High) == "high");
    CHECK(threatLevelToString(ThreatLevel::Critical) == "critical");

    CHECK(threatLevelFromString("low") == ThreatLevel::Low);
    CHECK(threatLevelFromString("medium") == ThreatLevel::Medium);
    CHECK(threatLevelFromString("high") == ThreatLevel::High);
    CHECK(threatLevelFromString("critical") == ThreatLevel::Critical);
    CHECK(threatLevelFromString("unknown") == ThreatLevel::Medium);
}
