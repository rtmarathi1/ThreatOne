#include "ai/ThreatClassifier.h"

#include <algorithm>
#include <cmath>

namespace ThreatOne::AI {

ThreatClassifier::ThreatClassifier()
    : logger_(Core::Logger::instance().getModuleLogger("ThreatClassifier"))
{
    logger_.info("ThreatClassifier initialized");
}

ClassificationResult ThreatClassifier::classify(const FileFeatures& fileFeatures,
                                                 const BehaviorFeatures& behaviorFeatures) const {
    // Build a combined feature vector from both inputs
    FeatureExtractor extractor;
    FeatureVector combined = extractor.toFeatureVector(fileFeatures);
    FeatureVector behaviorVec = extractor.toFeatureVector(behaviorFeatures);
    for (const auto& [key, value] : behaviorVec) {
        combined[key] = value;
    }
    return classifyFromVector(combined);
}

ClassificationResult ThreatClassifier::classifyFromVector(const FeatureVector& features) const {
    std::lock_guard<std::mutex> lock(mutex_);

    // Evaluate all category scores
    std::vector<CategoryScore> scores;
    scores.push_back(scoreRansomware(features));
    scores.push_back(scoreTrojan(features));
    scores.push_back(scoreWorm(features));
    scores.push_back(scoreRootkit(features));
    scores.push_back(scoreAdware(features));
    scores.push_back(scorePUP(features));
    scores.push_back(scoreExploit(features));
    scores.push_back(scoreMalware(features));
    scores.push_back(scoreBenign(features));

    // Sort by score descending
    std::sort(scores.begin(), scores.end(),
              [](const CategoryScore& a, const CategoryScore& b) {
                  return a.score > b.score;
              });

    ClassificationResult result;

    // If the top score is below a minimum threshold, classify as Unknown
    const double minConfidence = 0.2;
    if (scores.empty() || scores[0].score < minConfidence) {
        result.category = ThreatCategory::Unknown;
        result.confidence = 0.0;
        return result;
    }

    result.category = scores[0].category;
    result.confidence = std::min(scores[0].score, 1.0);
    result.indicators = scores[0].matchedIndicators;

    // Add secondary categories (those with score > 0.3 and not the primary)
    for (size_t i = 1; i < scores.size(); ++i) {
        if (scores[i].score > 0.3) {
            result.secondaryCategories.push_back(scores[i].category);
        }
    }

    logger_.debug("Classified as {} with confidence {:.2f}",
                  categoryToString(result.category), result.confidence);
    return result;
}

std::string ThreatClassifier::categoryToString(ThreatCategory category) {
    switch (category) {
        case ThreatCategory::Malware:     return "Malware";
        case ThreatCategory::PUP:         return "PUP";
        case ThreatCategory::Adware:      return "Adware";
        case ThreatCategory::Ransomware:  return "Ransomware";
        case ThreatCategory::Trojan:      return "Trojan";
        case ThreatCategory::Worm:        return "Worm";
        case ThreatCategory::Rootkit:     return "Rootkit";
        case ThreatCategory::Exploit:     return "Exploit";
        case ThreatCategory::Benign:      return "Benign";
        case ThreatCategory::Unknown:     return "Unknown";
    }
    return "Unknown";
}

ThreatCategory ThreatClassifier::stringToCategory(const std::string& name) {
    if (name == "Malware")     return ThreatCategory::Malware;
    if (name == "PUP")         return ThreatCategory::PUP;
    if (name == "Adware")      return ThreatCategory::Adware;
    if (name == "Ransomware")  return ThreatCategory::Ransomware;
    if (name == "Trojan")      return ThreatCategory::Trojan;
    if (name == "Worm")        return ThreatCategory::Worm;
    if (name == "Rootkit")     return ThreatCategory::Rootkit;
    if (name == "Exploit")     return ThreatCategory::Exploit;
    if (name == "Benign")      return ThreatCategory::Benign;
    return ThreatCategory::Unknown;
}

// Ransomware: high entropy + file operations + crypto indicators
ThreatClassifier::CategoryScore ThreatClassifier::scoreRansomware(const FeatureVector& features) const {
    CategoryScore result;
    result.category = ThreatCategory::Ransomware;

    double entropy = getFeature(features, "entropy");
    double suspiciousStrings = getFeature(features, "suspiciousStringCount");
    double importCount = getFeature(features, "importCount");
    double eventFrequency = getFeature(features, "eventFrequency");
    double suspiciousScore = getFeature(features, "suspiciousStringScore");

    // High entropy suggests encrypted data
    if (entropy > 7.0) {
        result.score += 0.3;
        result.matchedIndicators.push_back("high_entropy");
    }

    // Crypto-related APIs and strings
    if (suspiciousStrings > 5) {
        result.score += 0.2;
        result.matchedIndicators.push_back("crypto_api_usage");
    }

    // High import count (file system + crypto APIs)
    if (importCount > 30) {
        result.score += 0.15;
        result.matchedIndicators.push_back("high_import_count");
    }

    // Rapid file operations (high event frequency)
    if (eventFrequency > 10.0) {
        result.score += 0.25;
        result.matchedIndicators.push_back("rapid_file_operations");
    }

    // Suspicious string score adds weight
    if (suspiciousScore > 3.0) {
        result.score += 0.1;
        result.matchedIndicators.push_back("suspicious_string_patterns");
    }

    return result;
}

// Trojan: network APIs + hidden execution + privilege escalation
ThreatClassifier::CategoryScore ThreatClassifier::scoreTrojan(const FeatureVector& features) const {
    CategoryScore result;
    result.category = ThreatCategory::Trojan;

    double importCount = getFeature(features, "importCount");
    double urlCount = getFeature(features, "urlCount");
    double suspiciousStrings = getFeature(features, "suspiciousStringCount");
    double entropy = getFeature(features, "entropy");

    // Network-related imports
    if (importCount > 20 && urlCount > 0) {
        result.score += 0.3;
        result.matchedIndicators.push_back("network_api_imports");
    }

    // URLs in binary suggest C&C communication
    if (urlCount > 2) {
        result.score += 0.25;
        result.matchedIndicators.push_back("embedded_urls");
    }

    // Hidden functionality indicators
    if (suspiciousStrings > 8) {
        result.score += 0.2;
        result.matchedIndicators.push_back("hidden_functionality");
    }

    // Moderate entropy (packed but not fully encrypted)
    if (entropy > 5.0 && entropy < 7.5) {
        result.score += 0.15;
        result.matchedIndicators.push_back("packed_binary");
    }

    return result;
}

// Worm: self-replication + network scanning patterns
ThreatClassifier::CategoryScore ThreatClassifier::scoreWorm(const FeatureVector& features) const {
    CategoryScore result;
    result.category = ThreatCategory::Worm;

    double urlCount = getFeature(features, "urlCount");
    double importCount = getFeature(features, "importCount");
    double eventFrequency = getFeature(features, "eventFrequency");
    double uniqueEventTypes = getFeature(features, "uniqueEventTypes");

    // Network scanning (many URLs or connection targets)
    if (urlCount > 5) {
        result.score += 0.3;
        result.matchedIndicators.push_back("network_scanning");
    }

    // Self-replication (file creation + network combo)
    if (importCount > 25 && urlCount > 3) {
        result.score += 0.25;
        result.matchedIndicators.push_back("self_replication_pattern");
    }

    // High activity with diverse event types
    if (eventFrequency > 5.0 && uniqueEventTypes > 5) {
        result.score += 0.2;
        result.matchedIndicators.push_back("high_activity_diversity");
    }

    return result;
}

// Rootkit: kernel API hooks + stealth indicators
ThreatClassifier::CategoryScore ThreatClassifier::scoreRootkit(const FeatureVector& features) const {
    CategoryScore result;
    result.category = ThreatCategory::Rootkit;

    double importCount = getFeature(features, "importCount");
    double suspiciousStrings = getFeature(features, "suspiciousStringCount");
    double registryPaths = getFeature(features, "registryPathCount");
    double entropy = getFeature(features, "entropy");

    // Kernel-level API usage (high imports suggest system calls)
    if (importCount > 40) {
        result.score += 0.3;
        result.matchedIndicators.push_back("kernel_api_hooks");
    }

    // Registry manipulation for persistence
    if (registryPaths > 3) {
        result.score += 0.25;
        result.matchedIndicators.push_back("registry_manipulation");
    }

    // Stealth indicators (suspicious strings related to hiding)
    if (suspiciousStrings > 10) {
        result.score += 0.2;
        result.matchedIndicators.push_back("stealth_indicators");
    }

    // Low entropy (native code, not packed)
    if (entropy < 5.0 && importCount > 30) {
        result.score += 0.15;
        result.matchedIndicators.push_back("native_code_high_imports");
    }

    return result;
}

// Adware: browser manipulation + ad network URLs
ThreatClassifier::CategoryScore ThreatClassifier::scoreAdware(const FeatureVector& features) const {
    CategoryScore result;
    result.category = ThreatCategory::Adware;

    double urlCount = getFeature(features, "urlCount");
    double suspiciousStrings = getFeature(features, "suspiciousStringCount");
    double entropy = getFeature(features, "entropy");
    double importCount = getFeature(features, "importCount");

    // Many URLs (ad networks, tracking)
    if (urlCount > 3) {
        result.score += 0.35;
        result.matchedIndicators.push_back("ad_network_urls");
    }

    // Low threat indicators (not heavily obfuscated)
    if (entropy < 6.0 && suspiciousStrings < 5) {
        result.score += 0.2;
        result.matchedIndicators.push_back("low_obfuscation");
    }

    // Moderate import count (UI/browser APIs)
    if (importCount > 10 && importCount < 30) {
        result.score += 0.15;
        result.matchedIndicators.push_back("browser_manipulation_apis");
    }

    return result;
}

// PUP: bundled installer patterns
ThreatClassifier::CategoryScore ThreatClassifier::scorePUP(const FeatureVector& features) const {
    CategoryScore result;
    result.category = ThreatCategory::PUP;

    double fileSize = getFeature(features, "fileSize");
    double importCount = getFeature(features, "importCount");
    double urlCount = getFeature(features, "urlCount");
    double entropy = getFeature(features, "entropy");
    double suspiciousStrings = getFeature(features, "suspiciousStringCount");

    // Large file size (bundled installer)
    if (fileSize > 1000000) {
        result.score += 0.2;
        result.matchedIndicators.push_back("large_bundled_installer");
    }

    // Some URLs but not excessive
    if (urlCount > 0 && urlCount <= 3) {
        result.score += 0.2;
        result.matchedIndicators.push_back("update_urls");
    }

    // Low entropy and low suspicious content
    if (entropy < 6.5 && suspiciousStrings < 3) {
        result.score += 0.25;
        result.matchedIndicators.push_back("low_threat_profile");
    }

    // Moderate imports
    if (importCount > 5 && importCount < 25) {
        result.score += 0.1;
        result.matchedIndicators.push_back("standard_installer_apis");
    }

    return result;
}

// Exploit: shellcode patterns + vulnerability indicators
ThreatClassifier::CategoryScore ThreatClassifier::scoreExploit(const FeatureVector& features) const {
    CategoryScore result;
    result.category = ThreatCategory::Exploit;

    double entropy = getFeature(features, "entropy");
    double fileSize = getFeature(features, "fileSize");
    double importCount = getFeature(features, "importCount");
    double suspiciousStrings = getFeature(features, "suspiciousStringCount");

    // High entropy in small file (shellcode)
    if (entropy > 6.5 && fileSize < 50000) {
        result.score += 0.35;
        result.matchedIndicators.push_back("shellcode_pattern");
    }

    // Memory manipulation APIs
    if (importCount > 15 && suspiciousStrings > 5) {
        result.score += 0.25;
        result.matchedIndicators.push_back("memory_manipulation_apis");
    }

    // Very small payload
    if (fileSize < 10000 && entropy > 5.0) {
        result.score += 0.2;
        result.matchedIndicators.push_back("small_payload");
    }

    return result;
}

// Generic malware: high overall suspicion that doesn't fit other categories
ThreatClassifier::CategoryScore ThreatClassifier::scoreMalware(const FeatureVector& features) const {
    CategoryScore result;
    result.category = ThreatCategory::Malware;

    double entropy = getFeature(features, "entropy");
    double importCount = getFeature(features, "importCount");
    double suspiciousStrings = getFeature(features, "suspiciousStringCount");
    double suspiciousScore = getFeature(features, "suspiciousStringScore");

    // High entropy
    if (entropy > 6.5) {
        result.score += 0.2;
        result.matchedIndicators.push_back("high_entropy");
    }

    // High import count
    if (importCount > 30) {
        result.score += 0.2;
        result.matchedIndicators.push_back("high_import_count");
    }

    // Suspicious strings
    if (suspiciousStrings > 5) {
        result.score += 0.2;
        result.matchedIndicators.push_back("suspicious_strings");
    }

    // Suspicious string score
    if (suspiciousScore > 2.0) {
        result.score += 0.15;
        result.matchedIndicators.push_back("high_suspicion_score");
    }

    return result;
}

// Benign: low indicators across the board
ThreatClassifier::CategoryScore ThreatClassifier::scoreBenign(const FeatureVector& features) const {
    CategoryScore result;
    result.category = ThreatCategory::Benign;

    double entropy = getFeature(features, "entropy");
    double importCount = getFeature(features, "importCount");
    double suspiciousStrings = getFeature(features, "suspiciousStringCount");
    double urlCount = getFeature(features, "urlCount");

    // Low entropy
    if (entropy < 5.0) {
        result.score += 0.3;
        result.matchedIndicators.push_back("low_entropy");
    }

    // Low import count
    if (importCount < 15) {
        result.score += 0.25;
        result.matchedIndicators.push_back("low_import_count");
    }

    // No suspicious strings
    if (suspiciousStrings == 0) {
        result.score += 0.25;
        result.matchedIndicators.push_back("no_suspicious_strings");
    }

    // No URLs
    if (urlCount == 0) {
        result.score += 0.2;
        result.matchedIndicators.push_back("no_embedded_urls");
    }

    return result;
}

double ThreatClassifier::getFeature(const FeatureVector& features,
                                     const std::string& name,
                                     double defaultValue) {
    auto it = features.find(name);
    if (it != features.end()) {
        return it->second;
    }
    return defaultValue;
}

} // namespace ThreatOne::AI
