#pragma once

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <chrono>

#include "core/Logger.h"

namespace ThreatOne::AI {

// A feature vector maps feature names to numeric values
using FeatureVector = std::map<std::string, double>;

// Features extracted from file analysis
struct FileFeatures {
    double entropy = 0.0;
    uint64_t fileSize = 0;
    uint32_t sectionCount = 0;
    uint32_t importCount = 0;
    uint32_t suspiciousStringCount = 0;
    double suspiciousStringScore = 0.0;
    bool hasPEHeaders = false;
    uint32_t urlCount = 0;
    uint32_t registryPathCount = 0;
};

// Features extracted from behavioral events
struct BehaviorFeatures {
    double eventFrequency = 0.0;        // Events per second
    double timingVariance = 0.0;        // Variance of inter-event times
    uint32_t sequenceLength = 0;        // Total events in sequence
    uint32_t uniqueEventTypes = 0;      // Number of distinct event types
    double avgInterEventTime = 0.0;     // Average time between events (ms)
    double maxBurstRate = 0.0;          // Maximum events per second in burst
};

// A behavioral event used as input to feature extraction
struct BehaviorEvent {
    std::string type;
    std::string source;
    std::string details;
    std::chrono::steady_clock::time_point timestamp = std::chrono::steady_clock::now();
};

class FeatureExtractor {
public:
    FeatureExtractor();
    ~FeatureExtractor() = default;

    // Extract features from raw file data
    [[nodiscard]] FileFeatures extractFileFeatures(const std::string& data) const;

    // Extract features from a sequence of behavioral events
    [[nodiscard]] BehaviorFeatures extractBehaviorFeatures(
        const std::vector<BehaviorEvent>& events) const;

    // Convert extracted features to a generic feature vector
    [[nodiscard]] FeatureVector toFeatureVector(const FileFeatures& features) const;
    [[nodiscard]] FeatureVector toFeatureVector(const BehaviorFeatures& features) const;

    // Utility: Calculate Shannon entropy of byte data
    [[nodiscard]] static double calculateEntropy(const std::string& data);

private:
    Core::ModuleLogger logger_;

    // Internal analysis helpers
    [[nodiscard]] uint32_t countSections(const std::string& data) const;
    [[nodiscard]] uint32_t countImports(const std::string& data) const;
    [[nodiscard]] uint32_t countSuspiciousStrings(const std::string& data) const;
    [[nodiscard]] double scoreSuspiciousStrings(const std::string& data) const;
    [[nodiscard]] uint32_t countUrls(const std::string& data) const;
    [[nodiscard]] uint32_t countRegistryPaths(const std::string& data) const;
    [[nodiscard]] bool detectPEHeaders(const std::string& data) const;
};

} // namespace ThreatOne::AI
