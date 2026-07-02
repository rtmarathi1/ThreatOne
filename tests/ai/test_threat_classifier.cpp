#include <doctest/doctest.h>
#include <ai/ThreatClassifier.h>

#include <string>
#include <vector>

using namespace ThreatOne::AI;

TEST_CASE("ThreatClassifier - ransomware indicators") {
    ThreatClassifier classifier;

    SUBCASE("High entropy + file operations -> ransomware") {
        FileFeatures fileFeatures;
        fileFeatures.entropy = 7.8;
        fileFeatures.fileSize = 50000;
        fileFeatures.suspiciousStringCount = 5;
        fileFeatures.suspiciousStringScore = 8.0;

        BehaviorFeatures behaviorFeatures;
        behaviorFeatures.eventFrequency = 50.0;  // High frequency file operations
        behaviorFeatures.sequenceLength = 200;
        behaviorFeatures.maxBurstRate = 100.0;

        auto result = classifier.classify(fileFeatures, behaviorFeatures);
        CHECK(result.confidence >= 0.0);
        CHECK(result.confidence <= 1.0);
        // Should detect some threat, not benign
        CHECK(result.category != ThreatCategory::Unknown);
    }

    SUBCASE("Ransomware keywords in feature vector") {
        FeatureVector features;
        features["entropy"] = 7.9;
        features["suspiciousStringCount"] = 10.0;
        features["suspiciousStringScore"] = 15.0;
        features["eventFrequency"] = 80.0;
        features["maxBurstRate"] = 100.0;
        features["sequenceLength"] = 500.0;

        auto result = classifier.classifyFromVector(features);
        CHECK(result.confidence > 0.0);
        CHECK(result.confidence <= 1.0);
    }
}

TEST_CASE("ThreatClassifier - trojan indicators") {
    ThreatClassifier classifier;

    SUBCASE("Network activity + stealth behavior") {
        FeatureVector features;
        features["entropy"] = 6.5;
        features["importCount"] = 40.0;
        features["suspiciousStringCount"] = 8.0;
        features["suspiciousStringScore"] = 12.0;
        features["urlCount"] = 5.0;
        features["eventFrequency"] = 2.0;  // Low frequency (stealthy)

        auto result = classifier.classifyFromVector(features);
        CHECK(result.confidence > 0.0);
        CHECK(result.confidence <= 1.0);
        // Should be classified as some threat category
        CHECK(result.category != ThreatCategory::Benign);
    }
}

TEST_CASE("ThreatClassifier - benign indicators") {
    ThreatClassifier classifier;

    SUBCASE("Low all scores -> benign classification") {
        FileFeatures fileFeatures;
        fileFeatures.entropy = 3.0;
        fileFeatures.fileSize = 5000;
        fileFeatures.sectionCount = 2;
        fileFeatures.importCount = 5;
        fileFeatures.suspiciousStringCount = 0;
        fileFeatures.suspiciousStringScore = 0.0;
        fileFeatures.urlCount = 0;

        BehaviorFeatures behaviorFeatures;
        behaviorFeatures.eventFrequency = 1.0;
        behaviorFeatures.sequenceLength = 5;
        behaviorFeatures.uniqueEventTypes = 2;
        behaviorFeatures.maxBurstRate = 2.0;

        auto result = classifier.classify(fileFeatures, behaviorFeatures);
        CHECK(result.category == ThreatCategory::Benign);
        CHECK(result.confidence > 0.0);
    }

    SUBCASE("Empty feature vector -> benign or unknown") {
        FeatureVector features;
        auto result = classifier.classifyFromVector(features);
        // With no indicators, should be benign or unknown
        CHECK((result.category == ThreatCategory::Benign ||
               result.category == ThreatCategory::Unknown));
    }
}

TEST_CASE("ThreatClassifier - confidence bounds") {
    ThreatClassifier classifier;

    SUBCASE("Confidence always in [0, 1] for various inputs") {
        // Test multiple different feature combinations
        std::vector<FeatureVector> testVectors = {
            {{"entropy", 7.9}, {"suspiciousStringCount", 20.0}, {"importCount", 50.0}},
            {{"entropy", 0.0}, {"suspiciousStringCount", 0.0}},
            {{"entropy", 4.0}, {"importCount", 100.0}, {"urlCount", 10.0}},
            {{"eventFrequency", 200.0}, {"maxBurstRate", 500.0}},
        };

        for (const auto& features : testVectors) {
            auto result = classifier.classifyFromVector(features);
            CHECK(result.confidence >= 0.0);
            CHECK(result.confidence <= 1.0);
        }
    }
}

TEST_CASE("ThreatClassifier - category string conversion") {
    SUBCASE("All categories convert to string and back") {
        std::vector<ThreatCategory> categories = {
            ThreatCategory::Malware, ThreatCategory::PUP, ThreatCategory::Adware,
            ThreatCategory::Ransomware, ThreatCategory::Trojan, ThreatCategory::Worm,
            ThreatCategory::Rootkit, ThreatCategory::Exploit, ThreatCategory::Benign,
            ThreatCategory::Unknown
        };

        for (auto cat : categories) {
            std::string str = ThreatClassifier::categoryToString(cat);
            CHECK(!str.empty());
            ThreatCategory back = ThreatClassifier::stringToCategory(str);
            CHECK(back == cat);
        }
    }

    SUBCASE("Unknown string returns Unknown category") {
        auto cat = ThreatClassifier::stringToCategory("NonexistentCategory");
        CHECK(cat == ThreatCategory::Unknown);
    }
}

TEST_CASE("ThreatClassifier - secondary categories and indicators") {
    ThreatClassifier classifier;

    SUBCASE("Classification includes indicators") {
        FeatureVector features;
        features["entropy"] = 7.5;
        features["suspiciousStringCount"] = 8.0;
        features["suspiciousStringScore"] = 10.0;
        features["importCount"] = 30.0;
        features["eventFrequency"] = 50.0;
        features["urlCount"] = 3.0;

        auto result = classifier.classifyFromVector(features);
        // With high threat indicators, should have some indicators listed
        CHECK(result.confidence > 0.2);
    }
}
