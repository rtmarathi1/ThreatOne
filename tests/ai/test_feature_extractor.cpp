#include <doctest/doctest.h>
#include <ai/FeatureExtractor.h>

#include <string>
#include <vector>
#include <cmath>
#include <random>
#include <chrono>

using namespace ThreatOne::AI;

TEST_CASE("FeatureExtractor - Shannon entropy calculation") {
    SUBCASE("All zeros gives zero entropy") {
        std::string data(1000, '\0');
        double entropy = FeatureExtractor::calculateEntropy(data);
        CHECK(entropy == doctest::Approx(0.0).epsilon(0.001));
    }

    SUBCASE("Single repeated byte gives zero entropy") {
        std::string data(500, 'A');
        double entropy = FeatureExtractor::calculateEntropy(data);
        CHECK(entropy == doctest::Approx(0.0).epsilon(0.001));
    }

    SUBCASE("Random data approaches maximum entropy (8.0)") {
        // Create data with all 256 byte values equally distributed
        std::string data;
        data.reserve(256 * 100);
        for (int repeat = 0; repeat < 100; ++repeat) {
            for (int b = 0; b < 256; ++b) {
                data.push_back(static_cast<char>(b));
            }
        }
        double entropy = FeatureExtractor::calculateEntropy(data);
        CHECK(entropy == doctest::Approx(8.0).epsilon(0.01));
    }

    SUBCASE("Two equally distributed bytes gives entropy of 1.0") {
        std::string data;
        for (int i = 0; i < 500; ++i) {
            data.push_back('A');
            data.push_back('B');
        }
        double entropy = FeatureExtractor::calculateEntropy(data);
        CHECK(entropy == doctest::Approx(1.0).epsilon(0.01));
    }

    SUBCASE("Empty data gives zero entropy") {
        double entropy = FeatureExtractor::calculateEntropy("");
        CHECK(entropy == doctest::Approx(0.0).epsilon(0.001));
    }

    SUBCASE("Four equally distributed bytes gives entropy of 2.0") {
        std::string data;
        for (int i = 0; i < 250; ++i) {
            data.push_back('A');
            data.push_back('B');
            data.push_back('C');
            data.push_back('D');
        }
        double entropy = FeatureExtractor::calculateEntropy(data);
        CHECK(entropy == doctest::Approx(2.0).epsilon(0.01));
    }
}

TEST_CASE("FeatureExtractor - file feature extraction") {
    FeatureExtractor extractor;

    SUBCASE("Simple text file has low entropy") {
        std::string content = "Hello world this is a simple text file with some content.";
        auto features = extractor.extractFileFeatures(content);
        CHECK(features.entropy < 5.0);
        CHECK(features.fileSize == content.size());
    }

    SUBCASE("File with suspicious strings is detected") {
        std::string content = "LoadLibrary GetProcAddress VirtualAlloc CreateRemoteThread ";
        content += "WriteProcessMemory http://malicious.com cmd.exe powershell ";
        content += "HKEY_LOCAL_MACHINE mimikatz password credential";
        auto features = extractor.extractFileFeatures(content);
        CHECK(features.suspiciousStringCount > 0);
        CHECK(features.suspiciousStringScore > 0.0);
    }

    SUBCASE("File with PE section markers detected") {
        std::string content = "MZ";
        content.resize(64, '\0');
        content += ".text\0.data\0.rdata\0.rsrc\0";
        auto features = extractor.extractFileFeatures(content);
        CHECK(features.sectionCount > 0);
    }

    SUBCASE("URL count detection") {
        std::string content = "Visit http://example.com and https://evil.com/payload for more";
        auto features = extractor.extractFileFeatures(content);
        CHECK(features.urlCount >= 2);
    }

    SUBCASE("Feature vector conversion preserves values") {
        FileFeatures features;
        features.entropy = 6.5;
        features.fileSize = 1024;
        features.sectionCount = 4;
        features.importCount = 15;
        features.suspiciousStringCount = 3;

        auto vec = extractor.toFeatureVector(features);
        CHECK(vec["entropy"] == doctest::Approx(6.5));
        CHECK(vec["fileSize"] == doctest::Approx(1024.0));
        CHECK(vec["sectionCount"] == doctest::Approx(4.0));
        CHECK(vec["importCount"] == doctest::Approx(15.0));
        CHECK(vec["suspiciousStringCount"] == doctest::Approx(3.0));
    }
}

TEST_CASE("FeatureExtractor - behavior feature extraction") {
    FeatureExtractor extractor;

    SUBCASE("Multiple events produce valid frequency") {
        std::vector<BehaviorEvent> events;
        auto baseTime = std::chrono::steady_clock::now();

        for (int i = 0; i < 10; ++i) {
            BehaviorEvent event;
            event.type = (i % 3 == 0) ? "file_write" : "registry_access";
            event.source = "process_" + std::to_string(i % 2);
            event.timestamp = baseTime + std::chrono::milliseconds(i * 100);
            events.push_back(event);
        }

        auto features = extractor.extractBehaviorFeatures(events);
        CHECK(features.sequenceLength == 10);
        CHECK(features.uniqueEventTypes >= 1);
        CHECK(features.eventFrequency > 0.0);
    }

    SUBCASE("Single event gives valid but minimal features") {
        std::vector<BehaviorEvent> events;
        BehaviorEvent event;
        event.type = "file_open";
        event.source = "process_1";
        events.push_back(event);

        auto features = extractor.extractBehaviorFeatures(events);
        CHECK(features.sequenceLength == 1);
        CHECK(features.uniqueEventTypes == 1);
    }

    SUBCASE("Empty events produce zero features") {
        std::vector<BehaviorEvent> events;
        auto features = extractor.extractBehaviorFeatures(events);
        CHECK(features.sequenceLength == 0);
        CHECK(features.eventFrequency == doctest::Approx(0.0));
    }

    SUBCASE("Behavior feature vector conversion") {
        BehaviorFeatures features;
        features.eventFrequency = 5.0;
        features.timingVariance = 2.5;
        features.sequenceLength = 20;
        features.uniqueEventTypes = 4;

        auto vec = extractor.toFeatureVector(features);
        CHECK(vec["eventFrequency"] == doctest::Approx(5.0));
        CHECK(vec["timingVariance"] == doctest::Approx(2.5));
        CHECK(vec["sequenceLength"] == doctest::Approx(20.0));
        CHECK(vec["uniqueEventTypes"] == doctest::Approx(4.0));
    }
}
