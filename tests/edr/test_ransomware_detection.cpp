#include <doctest/doctest.h>
#include <edr/RansomwareDetection.h>

#include <filesystem>
#include <fstream>
#include <random>

namespace fs = std::filesystem;
using namespace ThreatOne::EDR;

TEST_CASE("RansomwareDetection - known extension detection") {
    RansomwareDetection detector;

    SUBCASE("Known ransomware extensions are detected") {
        CHECK(detector.checkKnownExtensions("file.encrypted"));
        CHECK(detector.checkKnownExtensions("document.locked"));
        CHECK(detector.checkKnownExtensions("data.crypto"));
        CHECK(detector.checkKnownExtensions("photo.locky"));
        CHECK(detector.checkKnownExtensions("backup.cerber"));
        CHECK(detector.checkKnownExtensions("report.zepto"));
    }

    SUBCASE("Normal extensions are not flagged") {
        CHECK_FALSE(detector.checkKnownExtensions("file.txt"));
        CHECK_FALSE(detector.checkKnownExtensions("document.pdf"));
        CHECK_FALSE(detector.checkKnownExtensions("image.png"));
        CHECK_FALSE(detector.checkKnownExtensions("code.cpp"));
        CHECK_FALSE(detector.checkKnownExtensions("data.json"));
    }

    SUBCASE("Case insensitive detection") {
        CHECK(detector.checkKnownExtensions("file.ENCRYPTED"));
        CHECK(detector.checkKnownExtensions("file.Locked"));
    }

    SUBCASE("No extension returns false") {
        CHECK_FALSE(detector.checkKnownExtensions("noextension"));
        CHECK_FALSE(detector.checkKnownExtensions(""));
    }
}

TEST_CASE("RansomwareDetection - entropy calculation") {
    RansomwareDetection detector;

    SUBCASE("Empty data has zero entropy") {
        std::vector<uint8_t> emptyData;
        CHECK(detector.calculateDataEntropy(emptyData) == 0.0);
    }

    SUBCASE("Uniform data has zero entropy") {
        std::vector<uint8_t> uniform(1000, 0x41); // All 'A'
        double entropy = detector.calculateDataEntropy(uniform);
        CHECK(entropy == doctest::Approx(0.0));
    }

    SUBCASE("Random data has high entropy (close to 8)") {
        std::vector<uint8_t> random(10000);
        std::mt19937 gen(42);
        std::uniform_int_distribution<int> dist(0, 255);
        for (auto& b : random) {
            b = static_cast<uint8_t>(dist(gen));
        }
        double entropy = detector.calculateDataEntropy(random);
        CHECK(entropy > 7.5);
        CHECK(entropy <= 8.0);
    }

    SUBCASE("Text data has moderate entropy") {
        std::string text = "Hello World! This is a test string with some "
                           "repetition. Hello World again and again.";
        std::vector<uint8_t> textData(text.begin(), text.end());
        double entropy = detector.calculateDataEntropy(textData);
        CHECK(entropy > 2.0);
        CHECK(entropy < 6.0);
    }

    SUBCASE("File entropy calculation works") {
        auto tempDir = fs::temp_directory_path() / "threatone_test_entropy";
        fs::create_directories(tempDir);
        auto testFile = tempDir / "test.bin";

        // Write random-looking data
        std::ofstream out(testFile, std::ios::binary);
        std::mt19937 gen(123);
        std::uniform_int_distribution<int> dist(0, 255);
        for (int i = 0; i < 1000; i++) {
            char c = static_cast<char>(dist(gen));
            out.write(&c, 1);
        }
        out.close();

        double entropy = detector.calculateFileEntropy(testFile.string());
        CHECK(entropy > 7.0);

        fs::remove_all(tempDir);
    }
}

TEST_CASE("RansomwareDetection - ransom note detection") {
    RansomwareDetection detector;

    SUBCASE("Known ransom note filenames are detected") {
        CHECK(detector.isRansomNote("README_DECRYPT.txt"));
        CHECK(detector.isRansomNote("HOW_TO_RECOVER.html"));
        CHECK(detector.isRansomNote("DECRYPT_INSTRUCTION.txt"));
        CHECK(detector.isRansomNote("YOUR_FILES_ARE_ENCRYPTED.txt"));
    }

    SUBCASE("Normal filenames are not flagged") {
        CHECK_FALSE(detector.isRansomNote("readme.md"));
        CHECK_FALSE(detector.isRansomNote("document.txt"));
        CHECK_FALSE(detector.isRansomNote("main.cpp"));
    }
}

TEST_CASE("RansomwareDetection - file operation analysis") {
    RansomwareDetection detector;

    SUBCASE("File with ransomware extension triggers detection") {
        FileEvent event;
        event.path = "/home/user/documents/report.encrypted";
        event.action = "rename";
        event.processName = "suspect";

        auto result = detector.analyzeFileOperation(event);
        REQUIRE(result.has_value());
        CHECK(result->confidence == "high");
    }

    SUBCASE("Normal file operation does not trigger") {
        FileEvent event;
        event.path = "/home/user/documents/report.pdf";
        event.action = "write";
        event.processName = "libreoffice";

        auto result = detector.analyzeFileOperation(event);
        CHECK_FALSE(result.has_value());
    }

    SUBCASE("Ransom note creation triggers detection") {
        FileEvent event;
        event.path = "/home/user/README_DECRYPT.txt";
        event.action = "create";
        event.processName = "ransomware";

        auto result = detector.analyzeFileOperation(event);
        REQUIRE(result.has_value());
        CHECK(result->indicator == "ransom_note_creation");
    }

    SUBCASE("Mass rename detection") {
        detector.setMassRenameThreshold(5);
        detector.setMassRenameWindow(std::chrono::seconds(60));

        std::optional<RansomwareIndicator> lastResult;
        for (int i = 0; i < 6; i++) {
            FileEvent event;
            event.path = "/home/user/file_" + std::to_string(i) + ".txt";
            event.action = "rename";
            event.processName = "encrypt";
            lastResult = detector.analyzeFileOperation(event);
        }

        // The last one should trigger mass rename
        REQUIRE(lastResult.has_value());
        CHECK(lastResult->indicator == "mass_file_rename");
    }
}

TEST_CASE("RansomwareDetection - statistics") {
    RansomwareDetection detector;

    FileEvent event1;
    event1.path = "/test/file.encrypted";
    event1.action = "rename";
    (void)detector.analyzeFileOperation(event1);

    FileEvent event2;
    event2.path = "/test/normal.txt";
    event2.action = "write";
    (void)detector.analyzeFileOperation(event2);

    auto stats = detector.getDetectionStats();
    CHECK(stats.totalFilesAnalyzed == 2);
    CHECK(stats.knownExtensionsDetected == 1);
}
