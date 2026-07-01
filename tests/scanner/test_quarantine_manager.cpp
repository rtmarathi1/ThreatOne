#include <doctest/doctest.h>
#include <scanner/QuarantineManager.h>

#include <fstream>
#include <filesystem>

using namespace ThreatOne::Scanner;

TEST_CASE("QuarantineManager operations") {
    auto tempDir = std::filesystem::temp_directory_path() / "threatone_test_quarantine";
    std::filesystem::remove_all(tempDir);

    SUBCASE("Quarantine a file") {
        auto quarantineDir = tempDir / "quarantine_q";
        auto filesDir = tempDir / "files_q";
        std::filesystem::create_directories(filesDir);

        QuarantineManager qm(quarantineDir);
        auto initResult = qm.initialize();
        REQUIRE(initResult.isOk());
        REQUIRE(std::filesystem::exists(quarantineDir));

        auto testFile = filesDir / "malware.exe";
        {
            std::ofstream f(testFile);
            f << "malicious content";
        }
        CHECK(std::filesystem::exists(testFile));

        auto result = qm.quarantine(testFile, "Trojan detected", "hash123");
        REQUIRE(result.isOk());

        auto entry = result.value();
        CHECK_FALSE(entry.id.empty());
        CHECK(entry.reason == "Trojan detected");
        CHECK(entry.hash == "hash123");
        CHECK_FALSE(entry.timestamp.empty());

        // Original file should be gone
        CHECK_FALSE(std::filesystem::exists(testFile));

        // Quarantined file should exist
        CHECK(std::filesystem::exists(entry.quarantinedPath));

        std::filesystem::remove_all(tempDir);
    }

    SUBCASE("Restore a quarantined file") {
        auto quarantineDir = tempDir / "quarantine_r";
        auto filesDir = tempDir / "files_r";
        std::filesystem::create_directories(filesDir);

        QuarantineManager qm(quarantineDir);
        qm.initialize();

        auto testFile = filesDir / "restore_test.txt";
        {
            std::ofstream f(testFile);
            f << "restore me";
        }

        auto qResult = qm.quarantine(testFile, "test reason");
        REQUIRE(qResult.isOk());
        auto entryId = qResult.value().id;

        CHECK_FALSE(std::filesystem::exists(testFile));

        auto restoreResult = qm.restore(entryId);
        REQUIRE(restoreResult.isOk());

        CHECK(std::filesystem::exists(testFile));
        // Verify content
        std::ifstream f(testFile);
        std::string content((std::istreambuf_iterator<char>(f)),
                            std::istreambuf_iterator<char>());
        CHECK(content == "restore me");

        std::filesystem::remove_all(tempDir);
    }

    SUBCASE("Permanent delete") {
        auto quarantineDir = tempDir / "quarantine_d";
        auto filesDir = tempDir / "files_d";
        std::filesystem::create_directories(filesDir);

        QuarantineManager qm(quarantineDir);
        qm.initialize();

        auto testFile = filesDir / "delete_test.txt";
        {
            std::ofstream f(testFile);
            f << "delete me";
        }

        auto qResult = qm.quarantine(testFile, "should be deleted");
        REQUIRE(qResult.isOk());
        auto entryId = qResult.value().id;
        auto qPath = qResult.value().quarantinedPath;

        CHECK(std::filesystem::exists(qPath));

        auto deleteResult = qm.permanentDelete(entryId);
        REQUIRE(deleteResult.isOk());

        CHECK_FALSE(std::filesystem::exists(qPath));
        CHECK_FALSE(std::filesystem::exists(quarantineDir / (entryId + ".json")));

        std::filesystem::remove_all(tempDir);
    }

    SUBCASE("List quarantine entries") {
        auto quarantineDir = tempDir / "quarantine_l";
        auto filesDir = tempDir / "files_l";
        std::filesystem::create_directories(filesDir);

        QuarantineManager qm(quarantineDir);
        qm.initialize();

        // Create and quarantine multiple files
        for (int i = 0; i < 3; ++i) {
            auto f = filesDir / ("listfile" + std::to_string(i) + ".txt");
            { std::ofstream out(f); out << "content" << i; }
            qm.quarantine(f, "reason" + std::to_string(i));
        }

        auto listResult = qm.listEntries();
        REQUIRE(listResult.isOk());
        CHECK(listResult.value().size() == 3);

        std::filesystem::remove_all(tempDir);
    }

    SUBCASE("Quarantine non-existent file fails") {
        auto quarantineDir = tempDir / "quarantine_n";
        auto filesDir = tempDir / "files_n";
        std::filesystem::create_directories(filesDir);

        QuarantineManager qm(quarantineDir);
        qm.initialize();

        auto result = qm.quarantine(filesDir / "nope.txt", "test");
        CHECK(result.isErr());

        std::filesystem::remove_all(tempDir);
    }

    SUBCASE("Delete non-existent entry fails") {
        auto quarantineDir = tempDir / "quarantine_ne";
        std::filesystem::create_directories(quarantineDir);

        QuarantineManager qm(quarantineDir);
        qm.initialize();

        auto result = qm.permanentDelete("nonexistentid");
        CHECK(result.isErr());

        std::filesystem::remove_all(tempDir);
    }
}
