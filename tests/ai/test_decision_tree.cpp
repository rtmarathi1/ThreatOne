#include <doctest/doctest.h>
#include <ai/DecisionTreeClassifier.h>

#include <string>

using namespace ThreatOne::AI;

TEST_CASE("DecisionTreeClassifier - tree construction") {
    DecisionTreeClassifier classifier;

    SUBCASE("Tree has expected number of nodes after construction") {
        CHECK(classifier.getTreeSize() == 13);
    }

    SUBCASE("getName returns expected model name") {
        CHECK(classifier.getName() == "SecurityDecisionTree");
    }

    SUBCASE("getVersion returns non-empty version") {
        CHECK(!classifier.getVersion().empty());
        CHECK(classifier.getVersion() == "1.0.0");
    }

    SUBCASE("getMetadata returns valid info") {
        auto meta = classifier.getMetadata();
        CHECK(!meta.name.empty());
        CHECK(!meta.version.empty());
    }
}

TEST_CASE("DecisionTreeClassifier - prediction with known vectors") {
    DecisionTreeClassifier classifier;

    SUBCASE("High entropy + many suspicious strings -> malicious") {
        FeatureVector features;
        features["entropy"] = 7.5;
        features["suspiciousStringCount"] = 10.0;
        features["importCount"] = 5.0;
        features["suspiciousStringScore"] = 2.0;

        auto prediction = classifier.classify(features);
        CHECK(prediction.label == "malicious");
        CHECK(prediction.confidence == doctest::Approx(0.92));
    }

    SUBCASE("High entropy + few suspicious strings + many imports -> suspicious") {
        FeatureVector features;
        features["entropy"] = 7.5;
        features["suspiciousStringCount"] = 2.0;
        features["importCount"] = 50.0;
        features["suspiciousStringScore"] = 1.0;

        auto prediction = classifier.classify(features);
        CHECK(prediction.label == "suspicious");
        CHECK(prediction.confidence == doctest::Approx(0.78));
    }

    SUBCASE("Low entropy + low imports + low suspicious score -> benign") {
        FeatureVector features;
        features["entropy"] = 3.0;
        features["suspiciousStringCount"] = 1.0;
        features["importCount"] = 5.0;
        features["suspiciousStringScore"] = 1.0;

        auto prediction = classifier.classify(features);
        CHECK(prediction.label == "benign");
        CHECK(prediction.confidence == doctest::Approx(0.95));
    }

    SUBCASE("High entropy only (compressed file) -> benign with low confidence") {
        FeatureVector features;
        features["entropy"] = 7.8;
        features["suspiciousStringCount"] = 0.0;
        features["importCount"] = 5.0;
        features["suspiciousStringScore"] = 0.0;

        auto prediction = classifier.classify(features);
        CHECK(prediction.label == "benign");
        CHECK(prediction.confidence == doctest::Approx(0.65));
    }

    SUBCASE("Low entropy + many imports + suspicious strings -> suspicious") {
        FeatureVector features;
        features["entropy"] = 4.0;
        features["suspiciousStringCount"] = 5.0;
        features["importCount"] = 40.0;
        features["suspiciousStringScore"] = 3.0;

        auto prediction = classifier.classify(features);
        CHECK(prediction.label == "suspicious");
        CHECK(prediction.confidence == doctest::Approx(0.80));
    }
}

TEST_CASE("DecisionTreeClassifier - explain") {
    DecisionTreeClassifier classifier;

    SUBCASE("Explain returns human-readable decision path") {
        FeatureVector features;
        features["entropy"] = 7.5;
        features["suspiciousStringCount"] = 10.0;
        features["importCount"] = 5.0;

        std::string explanation = classifier.explain(features);
        CHECK(!explanation.empty());
        // Should mention the feature names used in decisions
        CHECK(explanation.find("entropy") != std::string::npos);
    }

    SUBCASE("Different inputs produce different explanations") {
        FeatureVector malicious;
        malicious["entropy"] = 7.5;
        malicious["suspiciousStringCount"] = 10.0;

        FeatureVector benign;
        benign["entropy"] = 2.0;
        benign["suspiciousStringCount"] = 0.0;
        benign["importCount"] = 5.0;
        benign["suspiciousStringScore"] = 1.0;

        std::string explainMal = classifier.explain(malicious);
        std::string explainBen = classifier.explain(benign);
        CHECK(explainMal != explainBen);
    }
}

TEST_CASE("DecisionTreeClassifier - edge cases") {
    DecisionTreeClassifier classifier;

    SUBCASE("Empty feature vector produces a valid prediction") {
        FeatureVector features;
        auto prediction = classifier.classify(features);
        CHECK(!prediction.label.empty());
        CHECK(prediction.confidence >= 0.0);
        CHECK(prediction.confidence <= 1.0);
    }

    SUBCASE("Boundary values - entropy exactly at 7.0") {
        FeatureVector features;
        features["entropy"] = 7.0;  // <= 7.0 goes to left child
        features["suspiciousStringCount"] = 0.0;
        features["importCount"] = 5.0;
        features["suspiciousStringScore"] = 1.0;

        auto prediction = classifier.classify(features);
        // At threshold, goes to left child (low entropy branch)
        CHECK(prediction.label == "benign");
    }

    SUBCASE("Predict returns raw scores vector") {
        FeatureVector features;
        features["entropy"] = 7.5;
        features["suspiciousStringCount"] = 10.0;

        // predict() from IMLModel interface
        DecisionTreeClassifier nonConst;
        auto scores = nonConst.predict(features);
        CHECK(!scores.empty());
    }

    SUBCASE("Load with empty data rebuilds default tree") {
        DecisionTreeClassifier classifier2;
        bool loaded = classifier2.load("");
        CHECK(loaded == true);
        CHECK(classifier2.getTreeSize() == 13);
    }
}
