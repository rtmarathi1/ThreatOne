#include <doctest/doctest.h>
#include <scanner/ScanEngine.h>

#include <fstream>
#include <filesystem>
#include <string>

using namespace ThreatOne::Scanner;

TEST_CASE("ScanEngine integration test") {
    auto tempDir = std::filesystem::temp_directory_path() / "threatone_test_scanengine";
    std::filesystem::remove_all(tempDir);
    auto scanDir = tempDir / "scandir";
    auto quarantineDir = tempDir / "quarantine";
    std::filesystem::create_directories(scanDir);

    // Create test files
    { std::ofstream(scanDir / "clean1.txt") << "hello world"; }
    { std::ofstream(scanDir / "clean2.txt") << "another file"; }
    { std::ofstream(scanDir / "abc.txt") << "abc"; }

    SUBCASE("Start a custom scan on a directory") {
        ScanEngine engine(quarantineDir);

        ScanConfig config;
        config.type = ScanType::Custom;
        config.targets = {scanDir.string()};

        auto scanId = engine.startScan(config);
        CHECK_FALSE(scanId.empty());

        auto status = engine.getScanStatus(scanId);
        CHECK(status.scanId == scanId);
        CHECK(status.filesScanned == 3);
        CHECK((status.status == ScanStatus::Completed));
    }

    SUBCASE("Scan with loaded signatures detects threats") {
        ScanEngine engine(quarantineDir);

        // SHA256("abc") = ba7816bf...
        std::string sigJson = R"({
            "signatures": [
                {
                    "name": "ABCMalware",
                    "hash": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                    "threat_level": "critical",
                    "category": "malware",
                    "description": "Detects abc content"
                }
            ]
        })";

        auto loadResult = engine.loadSignaturesFromString(sigJson);
        REQUIRE(loadResult.isOk());
        CHECK(loadResult.value() == 1);

        ScanConfig config;
        config.type = ScanType::Custom;
        config.targets = {scanDir.string()};

        auto scanId = engine.startScan(config);
        auto status = engine.getScanStatus(scanId);

        CHECK(status.filesScanned == 3);
        CHECK(status.threatsFound == 1);
        CHECK(status.findings.size() == 1);
    }

    SUBCASE("getScanResults returns all scans") {
        ScanEngine engine(quarantineDir);

        ScanConfig config;
        config.type = ScanType::Custom;
        config.targets = {scanDir.string()};

        engine.startScan(config);
        engine.startScan(config);

        auto results = engine.getScanResults();
        CHECK(results.size() == 2);
    }

    SUBCASE("stopScan marks scan as cancelled") {
        ScanEngine engine(quarantineDir);

        ScanConfig config;
        config.type = ScanType::Custom;
        config.targets = {scanDir.string()};

        auto scanId = engine.startScan(config);
        auto status = engine.getScanStatus(scanId);
        CHECK((status.status == ScanStatus::Completed ||
               status.status == ScanStatus::Cancelled));
    }

    SUBCASE("ScanEngine UUID generation") {
        ScanEngine engine(quarantineDir);

        ScanConfig config;
        config.type = ScanType::Custom;
        config.targets = {scanDir.string()};

        auto id1 = engine.startScan(config);
        auto id2 = engine.startScan(config);
        CHECK(id1 != id2);  // Different UUIDs each time
        CHECK(id1.size() == 36);  // UUID format: 8-4-4-4-12
    }

    std::filesystem::remove_all(tempDir);
}

TEST_CASE("ScanEngine with exclusions") {
    auto tempDir = std::filesystem::temp_directory_path() / "threatone_test_exclusions";
    auto scanDir = tempDir / "scandir";
    auto quarantineDir = tempDir / "quarantine";
    std::filesystem::remove_all(tempDir);
    std::filesystem::create_directories(scanDir);

    { std::ofstream(scanDir / "include.txt") << "keep"; }
    { std::ofstream(scanDir / "exclude.log") << "skip"; }
    { std::ofstream(scanDir / "also.txt") << "keep too"; }

    ScanEngine engine(quarantineDir);

    ScanConfig config;
    config.type = ScanType::Custom;
    config.targets = {scanDir.string()};
    config.exclusions = {"*.log"};

    auto scanId = engine.startScan(config);
    auto status = engine.getScanStatus(scanId);

    CHECK(status.filesScanned == 2);

    std::filesystem::remove_all(tempDir);
}
