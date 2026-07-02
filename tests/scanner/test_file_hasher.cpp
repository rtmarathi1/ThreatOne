#include <doctest/doctest.h>
#include <scanner/FileHasher.h>

#include <fstream>
#include <filesystem>
#include <cstdint>
#include <vector>

using namespace ThreatOne::Scanner;

TEST_CASE("SHA256 known test vectors") {
    SUBCASE("Empty string hash") {
        auto result = FileHasher::hashString("", HashAlgorithm::SHA256);
        REQUIRE(result.isOk());
        CHECK(result.value() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    SUBCASE("abc hash") {
        auto result = FileHasher::hashString("abc", HashAlgorithm::SHA256);
        REQUIRE(result.isOk());
        CHECK(result.value() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    SUBCASE("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") {
        auto result = FileHasher::hashString(
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            HashAlgorithm::SHA256);
        REQUIRE(result.isOk());
        CHECK(result.value() == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    }
}

TEST_CASE("SHA256 buffer hashing") {
    SUBCASE("Empty buffer") {
        std::vector<uint8_t> data;
        auto result = FileHasher::hashBuffer(data, HashAlgorithm::SHA256);
        REQUIRE(result.isOk());
        CHECK(result.value() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    SUBCASE("Known data buffer") {
        std::vector<uint8_t> data = {'a', 'b', 'c'};
        auto result = FileHasher::hashBuffer(data, HashAlgorithm::SHA256);
        REQUIRE(result.isOk());
        CHECK(result.value() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}

TEST_CASE("SHA256 file hashing") {
    auto tempDir = std::filesystem::temp_directory_path() / "threatone_test_hasher";
    std::filesystem::create_directories(tempDir);

    SUBCASE("Hash a file with known content") {
        auto testFile = tempDir / "test.txt";
        {
            std::ofstream f(testFile);
            f << "abc";
        }

        auto result = FileHasher::hashFile(testFile, HashAlgorithm::SHA256);
        REQUIRE(result.isOk());
        CHECK(result.value() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

        std::filesystem::remove(testFile);
    }

    SUBCASE("Hash non-existent file returns error") {
        auto result = FileHasher::hashFile(tempDir / "nonexistent.txt", HashAlgorithm::SHA256);
        CHECK(result.isErr());
    }

    SUBCASE("Hash empty file") {
        auto testFile = tempDir / "empty.txt";
        {
            std::ofstream f(testFile);
            // Write nothing
        }

        auto result = FileHasher::hashFile(testFile, HashAlgorithm::SHA256);
        REQUIRE(result.isOk());
        CHECK(result.value() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        std::filesystem::remove(testFile);
    }

    std::filesystem::remove_all(tempDir);
}

TEST_CASE("BLAKE3 placeholder") {
    SUBCASE("Returns a valid 64-character hex string") {
        auto result = FileHasher::hashString("test", HashAlgorithm::BLAKE3);
        REQUIRE(result.isOk());
        CHECK(result.value().size() == 64);
    }

    SUBCASE("Same input produces same output") {
        auto r1 = FileHasher::hashString("hello", HashAlgorithm::BLAKE3);
        auto r2 = FileHasher::hashString("hello", HashAlgorithm::BLAKE3);
        REQUIRE(r1.isOk());
        REQUIRE(r2.isOk());
        CHECK(r1.value() == r2.value());
    }

    SUBCASE("Different input produces different output") {
        auto r1 = FileHasher::hashString("hello", HashAlgorithm::BLAKE3);
        auto r2 = FileHasher::hashString("world", HashAlgorithm::BLAKE3);
        REQUIRE(r1.isOk());
        REQUIRE(r2.isOk());
        CHECK(r1.value() != r2.value());
    }
}
