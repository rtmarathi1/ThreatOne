#pragma once

#include <string>
#include <vector>

#include "ai/FeatureExtractor.h"

namespace ThreatOne::AI {

// Metadata about a trained model
struct ModelMetadata {
    std::string name;
    std::string version;
    double accuracy = 0.0;
    std::string lastUpdated;
    std::string description;
};

// Result of a model prediction
struct ModelPrediction {
    std::string label;
    double confidence = 0.0;
    std::vector<std::string> explanations;
};

// Abstract interface for all ML models
class IMLModel {
public:
    virtual ~IMLModel() = default;

    // Load model from serialized data (e.g., JSON string)
    virtual bool load(const std::string& modelData) = 0;

    // Predict on a feature vector, returning raw output scores
    virtual std::vector<double> predict(const FeatureVector& features) = 0;

    // Explain the prediction for a given feature vector
    virtual std::string explain(const FeatureVector& features) = 0;

    // Get model version string
    virtual std::string getVersion() = 0;

    // Get model name
    virtual std::string getName() = 0;

    // Get model metadata
    virtual ModelMetadata getMetadata() = 0;
};

} // namespace ThreatOne::AI
