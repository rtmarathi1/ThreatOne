#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>

#include "ai/FeatureExtractor.h"
#include "core/Logger.h"

namespace ThreatOne::AI {

// Categories of threats
enum class ThreatCategory {
    Malware,
    PUP,
    Adware,
    Ransomware,
    Trojan,
    Worm,
    Rootkit,
    Exploit,
    Benign,
    Unknown
};

// Result of threat classification
struct ClassificationResult {
    ThreatCategory category = ThreatCategory::Unknown;
    double confidence = 0.0;
    std::vector<ThreatCategory> secondaryCategories;
    std::vector<std::string> indicators;
};

class ThreatClassifier {
public:
    ThreatClassifier();
    ~ThreatClassifier() = default;

    // Classify based on file and behavior features
    [[nodiscard]] ClassificationResult classify(const FileFeatures& fileFeatures,
                                                 const BehaviorFeatures& behaviorFeatures) const;

    // Classify from a generic feature vector
    [[nodiscard]] ClassificationResult classifyFromVector(const FeatureVector& features) const;

    // Convert category enum to string
    [[nodiscard]] static std::string categoryToString(ThreatCategory category);

    // Convert string to category enum
    [[nodiscard]] static ThreatCategory stringToCategory(const std::string& name);

private:
    mutable std::mutex mutex_;
    Core::ModuleLogger logger_;

    // Scoring structure for each category
    struct CategoryScore {
        ThreatCategory category;
        double score = 0.0;
        std::vector<std::string> matchedIndicators;
    };

    // Heuristic rule evaluators for each category
    [[nodiscard]] CategoryScore scoreRansomware(const FeatureVector& features) const;
    [[nodiscard]] CategoryScore scoreTrojan(const FeatureVector& features) const;
    [[nodiscard]] CategoryScore scoreWorm(const FeatureVector& features) const;
    [[nodiscard]] CategoryScore scoreRootkit(const FeatureVector& features) const;
    [[nodiscard]] CategoryScore scoreAdware(const FeatureVector& features) const;
    [[nodiscard]] CategoryScore scorePUP(const FeatureVector& features) const;
    [[nodiscard]] CategoryScore scoreExploit(const FeatureVector& features) const;
    [[nodiscard]] CategoryScore scoreMalware(const FeatureVector& features) const;
    [[nodiscard]] CategoryScore scoreBenign(const FeatureVector& features) const;

    // Get feature value with default
    [[nodiscard]] static double getFeature(const FeatureVector& features,
                                            const std::string& name,
                                            double defaultValue = 0.0);
};

} // namespace ThreatOne::AI
