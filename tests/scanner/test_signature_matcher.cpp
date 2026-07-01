#include <doctest/doctest.h>
#include <scanner/SignatureMatcher.h>

#include <fstream>
#include <filesystem>

using namespace ThreatOne::Scanner;

TEST_CASE("SignatureMatcher file matching") {
    auto tempDir = std::filesystem::temp_directory_path() / "threatone_test_matcher";
    std::filesystem::create_directories(tempDir);

    // Create test file with content "abc"
    auto testFile = tempDir / "test_abc.txt";
    {
        std::ofstream f(testFile);
        f << "abc";
    }

    // SHA256 of "abc" is known
    std::string abcHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    SUBCASE("File matches a signature") {
        SignatureDatabase db;
        SignatureMatcher matcher(db);

        Signature sig;
        sig.name = "ABCMalware";
        sig.hash = abcHash;
        sig.threatLevel = ThreatLevel::High;
        sig.category = "malware";
        db.addSignature(sig);

        auto result = matcher.matchFile(testFile);
        REQUIRE(result.isOk());
        CHECK(result.value().matched == true);
        CHECK(result.value().signature.has_value());
        CHECK(result.value().signature->name == "ABCMalware");
    }

    SUBCASE("File does not match any signature") {
        SignatureDatabase db;
        SignatureMatcher matcher(db);
        // No signatures loaded
        auto result = matcher.matchFile(testFile);
        REQUIRE(result.isOk());
        CHECK(result.value().matched == false);
        CHECK_FALSE(result.value().signature.has_value());
    }

    SUBCASE("Non-existent file returns error") {
        SignatureDatabase db;
        SignatureMatcher matcher(db);
        auto result = matcher.matchFile(tempDir / "doesnotexist.bin");
        CHECK(result.isErr());
    }

    SUBCASE("Hash lookup matching") {
        SignatureDatabase db;
        SignatureMatcher matcher(db);

        Signature sig;
        sig.name = "KnownHash";
        sig.hash = "somehash123";
        sig.threatLevel = ThreatLevel::Critical;
        db.addSignature(sig);

        auto match = matcher.matchHash("somehash123", "/some/path");
        CHECK(match.matched == true);
        CHECK(match.filePath == "/some/path");
        CHECK(match.signature->name == "KnownHash");

        auto noMatch = matcher.matchHash("unknownhash", "/other/path");
        CHECK(noMatch.matched == false);
    }

    std::filesystem::remove_all(tempDir);
}

TEST_CASE("SignatureMatcher buffer matching") {
    SignatureDatabase db;
    SignatureMatcher matcher(db);

    // Add signature for empty buffer hash
    Signature sig;
    sig.name = "EmptyThreat";
    sig.hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    sig.threatLevel = ThreatLevel::Low;
    db.addSignature(sig);

    SUBCASE("Empty buffer matches empty hash signature") {
        std::vector<uint8_t> emptyData;
        auto result = matcher.matchBuffer(emptyData);
        REQUIRE(result.isOk());
        CHECK(result.value().matched == true);
        CHECK(result.value().signature->name == "EmptyThreat");
    }

    SUBCASE("Non-matching buffer") {
        std::vector<uint8_t> data = {1, 2, 3, 4, 5};
        auto result = matcher.matchBuffer(data);
        REQUIRE(result.isOk());
        CHECK(result.value().matched == false);
    }
}
