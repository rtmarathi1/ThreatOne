#include <doctest/doctest.h>
#include <scanner/FileEnumerator.h>

#include <fstream>
#include <filesystem>
#include <algorithm>

using namespace ThreatOne::Scanner;

TEST_CASE("FileEnumerator basic enumeration") {
    auto tempDir = std::filesystem::temp_directory_path() / "threatone_test_enum";
    std::filesystem::remove_all(tempDir);
    std::filesystem::create_directories(tempDir);

    // Create test file structure:
    // tempDir/file1.txt
    // tempDir/file2.log
    // tempDir/sub1/file3.txt
    // tempDir/sub1/sub2/file4.dat
    std::filesystem::create_directories(tempDir / "sub1" / "sub2");

    { std::ofstream(tempDir / "file1.txt") << "content1"; }
    { std::ofstream(tempDir / "file2.log") << "content2"; }
    { std::ofstream(tempDir / "sub1" / "file3.txt") << "content3"; }
    { std::ofstream(tempDir / "sub1" / "sub2" / "file4.dat") << "content4"; }

    FileEnumerator enumerator;

    SUBCASE("Enumerate all files recursively") {
        EnumerationConfig config;
        config.targets = {tempDir};

        auto result = enumerator.enumerate(config);
        REQUIRE(result.isOk());
        CHECK(result.value().size() == 4);
    }

    SUBCASE("Enumerate with exclusion pattern *.log") {
        EnumerationConfig config;
        config.targets = {tempDir};
        config.exclusionPatterns = {"*.log"};

        auto result = enumerator.enumerate(config);
        REQUIRE(result.isOk());
        CHECK(result.value().size() == 3);

        // Verify the .log file is excluded
        for (const auto& path : result.value()) {
            CHECK(path.extension() != ".log");
        }
    }

    SUBCASE("Enumerate with max depth 0 (top level only)") {
        EnumerationConfig config;
        config.targets = {tempDir};
        config.maxDepth = 0;

        auto result = enumerator.enumerate(config);
        REQUIRE(result.isOk());
        CHECK(result.value().size() == 2);  // Only file1.txt and file2.log
    }

    SUBCASE("Enumerate with max depth 1") {
        EnumerationConfig config;
        config.targets = {tempDir};
        config.maxDepth = 1;

        auto result = enumerator.enumerate(config);
        REQUIRE(result.isOk());
        CHECK(result.value().size() == 3);  // file1, file2, sub1/file3
    }

    SUBCASE("Enumerate non-existent target") {
        EnumerationConfig config;
        config.targets = {tempDir / "nonexistent"};

        auto result = enumerator.enumerate(config);
        REQUIRE(result.isOk());
        CHECK(result.value().empty());
    }

    SUBCASE("Enumerate single file target") {
        EnumerationConfig config;
        config.targets = {tempDir / "file1.txt"};

        auto result = enumerator.enumerate(config);
        REQUIRE(result.isOk());
        CHECK(result.value().size() == 1);
        CHECK(result.value()[0] == tempDir / "file1.txt");
    }

    SUBCASE("Multiple exclusion patterns") {
        EnumerationConfig config;
        config.targets = {tempDir};
        config.exclusionPatterns = {"*.log", "*.dat"};

        auto result = enumerator.enumerate(config);
        REQUIRE(result.isOk());
        CHECK(result.value().size() == 2);  // Only .txt files
    }

    SUBCASE("Callback-based enumeration") {
        EnumerationConfig config;
        config.targets = {tempDir};

        std::vector<std::filesystem::path> collected;
        auto result = enumerator.enumerateWithCallback(config,
            [&collected](const std::filesystem::path& p) {
                collected.push_back(p);
            });

        REQUIRE(result.isOk());
        CHECK(result.value() == 4);
        CHECK(collected.size() == 4);
    }

    std::filesystem::remove_all(tempDir);
}

TEST_CASE("FileEnumerator exclusion pattern matching") {
    SUBCASE("Simple extension match") {
        std::filesystem::path p("/some/path/file.txt");
        CHECK(FileEnumerator::matchesExclusion(p, {"*.txt"}) == true);
        CHECK(FileEnumerator::matchesExclusion(p, {"*.log"}) == false);
    }

    SUBCASE("Question mark wildcard") {
        std::filesystem::path p("/some/path/file1.txt");
        CHECK(FileEnumerator::matchesExclusion(p, {"file?.txt"}) == true);
        CHECK(FileEnumerator::matchesExclusion(p, {"file??.txt"}) == false);
    }

    SUBCASE("No patterns means no exclusion") {
        std::filesystem::path p("/some/path/file.txt");
        CHECK(FileEnumerator::matchesExclusion(p, {}) == false);
    }
}
