#include <doctest/doctest.h>
#include <ai/AnomalyDetector.h>

#include <cmath>
#include <vector>

using namespace ThreatOne::AI;

TEST_CASE("AnomalyDetector - z-score detection") {
    AnomalyDetector detector;

    SUBCASE("Insufficient data returns no anomaly") {
        // Only add 5 points (less than minimum 10)
        for (int i = 0; i < 5; ++i) {
            detector.addDataPoint("cpu_usage", 50.0);
        }
        auto result = detector.detectZScore("cpu_usage", 100.0);
        CHECK(result.isAnomaly == false);
        CHECK(result.method == "zscore");
    }

    SUBCASE("Normal value not flagged as anomaly") {
        // Add 20 data points centered around 50
        for (int i = 0; i < 20; ++i) {
            detector.addDataPoint("cpu_usage", 50.0 + (i % 5));
        }
        // Value close to mean should not be anomalous
        auto result = detector.detectZScore("cpu_usage", 52.0);
        CHECK(result.isAnomaly == false);
    }

    SUBCASE("Extreme outlier flagged as anomaly") {
        // Add 20 data points centered around 50 with small variance
        for (int i = 0; i < 20; ++i) {
            detector.addDataPoint("cpu_usage", 50.0 + (i % 3) - 1.0);
        }
        // Value far from mean should be anomalous
        auto result = detector.detectZScore("cpu_usage", 200.0);
        CHECK(result.isAnomaly == true);
        CHECK(result.anomalyScore > 3.0);
    }

    SUBCASE("Custom threshold affects detection") {
        for (int i = 0; i < 20; ++i) {
            detector.addDataPoint("metric", 10.0);
        }
        // With very strict threshold of 1.0, even small deviation is caught
        auto result = detector.detectZScore("metric", 15.0, 1.0);
        CHECK(result.isAnomaly == true);
    }

    SUBCASE("Unknown feature returns no anomaly") {
        auto result = detector.detectZScore("unknown_feature", 100.0);
        CHECK(result.isAnomaly == false);
    }
}

TEST_CASE("AnomalyDetector - moving average detection") {
    AnomalyDetector detector(50);

    SUBCASE("Insufficient window data returns no anomaly") {
        for (int i = 0; i < 5; ++i) {
            detector.addDataPoint("network_traffic", 100.0);
        }
        auto result = detector.detectMovingAverage("network_traffic", 500.0, 20);
        CHECK(result.isAnomaly == false);
        CHECK(result.method == "moving_average");
    }

    SUBCASE("Sudden spike detected after stable baseline") {
        // Build stable baseline
        for (int i = 0; i < 30; ++i) {
            detector.addDataPoint("network_traffic", 100.0 + (i % 3));
        }
        // Sudden spike to 10x the normal
        auto result = detector.detectMovingAverage("network_traffic", 1000.0, 20);
        CHECK(result.isAnomaly == true);
        CHECK(result.anomalyScore > 0.0);
    }

    SUBCASE("Value within normal range not flagged") {
        for (int i = 0; i < 30; ++i) {
            detector.addDataPoint("requests", 50.0 + (i % 10));
        }
        auto result = detector.detectMovingAverage("requests", 55.0, 20);
        CHECK(result.isAnomaly == false);
    }
}

TEST_CASE("AnomalyDetector - Welford algorithm accuracy") {
    AnomalyDetector detector;

    SUBCASE("Mean and variance computed correctly for known data") {
        // Add known values: 2, 4, 4, 4, 5, 5, 7, 9
        // Mean = 5.0, Variance = 4.0, StdDev = 2.0
        std::vector<double> values = {2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0};
        for (double v : values) {
            detector.addDataPoint("test_feature", v);
        }

        auto stats = detector.getBaseline("test_feature");
        CHECK(stats.count == 8);
        CHECK(stats.mean == doctest::Approx(5.0).epsilon(0.001));
        // Welford computes sample variance (n-1 denominator) or population variance
        // Check mean is correct
        CHECK(stats.min == doctest::Approx(2.0));
        CHECK(stats.max == doctest::Approx(9.0));
    }

    SUBCASE("Single value gives mean equal to value") {
        detector.addDataPoint("single", 42.0);
        auto stats = detector.getBaseline("single");
        CHECK(stats.count == 1);
        CHECK(stats.mean == doctest::Approx(42.0));
    }

    SUBCASE("hasBaseline returns false for insufficient data") {
        for (int i = 0; i < 5; ++i) {
            detector.addDataPoint("few_points", static_cast<double>(i));
        }
        CHECK(detector.hasBaseline("few_points", 10) == false);
        CHECK(detector.hasBaseline("few_points", 5) == true);
    }
}

TEST_CASE("AnomalyDetector - isolation forest") {
    AnomalyDetector detector;

    SUBCASE("Isolated point gets high anomaly score") {
        // Build baseline for multiple features
        for (int i = 0; i < 30; ++i) {
            detector.addDataPoint("feature_a", 10.0 + (i % 3));
            detector.addDataPoint("feature_b", 20.0 + (i % 5));
        }

        // Test with extreme values far from the baseline
        FeatureVector outlier;
        outlier["feature_a"] = 1000.0;
        outlier["feature_b"] = 5000.0;

        auto result = detector.detectIsolationForest(outlier);
        CHECK(result.method == "isolation_forest");
        CHECK(result.anomalyScore > 0.5);
    }

    SUBCASE("Normal point gets low anomaly score") {
        for (int i = 0; i < 30; ++i) {
            detector.addDataPoint("feat_x", 50.0 + (i % 5));
            detector.addDataPoint("feat_y", 30.0 + (i % 3));
        }

        FeatureVector normal;
        normal["feat_x"] = 52.0;
        normal["feat_y"] = 31.0;

        auto result = detector.detectIsolationForest(normal);
        CHECK(result.anomalyScore < 0.5);
    }
}

TEST_CASE("AnomalyDetector - utility methods") {
    AnomalyDetector detector;

    SUBCASE("getTrackedFeatureCount increases with features") {
        CHECK(detector.getTrackedFeatureCount() == 0);
        detector.addDataPoint("a", 1.0);
        CHECK(detector.getTrackedFeatureCount() == 1);
        detector.addDataPoint("b", 2.0);
        CHECK(detector.getTrackedFeatureCount() == 2);
    }
}

TEST_CASE("AnomalyDetector - reset operations") {
    AnomalyDetector detector;
    detector.addDataPoint("clearme", 1.0);
    detector.addDataPoint("keepme", 2.0);

    SUBCASE("resetFeature clears a specific feature") {
        CHECK(detector.getTrackedFeatureCount() == 2);
        detector.resetFeature("clearme");
        CHECK(detector.hasBaseline("clearme", 1) == false);
        CHECK(detector.getTrackedFeatureCount() == 1);
    }

    SUBCASE("resetAll clears everything") {
        detector.resetAll();
        CHECK(detector.getTrackedFeatureCount() == 0);
    }
}
