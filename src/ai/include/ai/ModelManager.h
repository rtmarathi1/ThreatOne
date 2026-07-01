#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <chrono>

#include "ai/IMLModel.h"
#include "core/Logger.h"

namespace ThreatOne::AI {

// Status of a managed model
enum class ModelStatus {
    Loaded,
    Unloaded,
    Error,
    Updating
};

// Extended information about a managed model
struct ModelInfo {
    std::string id;
    std::string name;
    std::string version;
    std::string type;
    ModelStatus status = ModelStatus::Unloaded;
    double accuracy = 0.0;
    std::chrono::steady_clock::time_point loadTime;
    uint64_t predictionCount = 0;
    double driftScore = 0.0;
};

class ModelManager {
public:
    ModelManager();
    ~ModelManager() = default;

    // Load a model with a given name and serialized data
    bool loadModel(const std::string& name, const std::string& modelData);

    // Unload a model by name
    bool unloadModel(const std::string& name);

    // Get a pointer to a loaded model (nullptr if not found)
    [[nodiscard]] IMLModel* getModel(const std::string& name) const;

    // List all managed models
    [[nodiscard]] std::vector<ModelInfo> listModels() const;

    // Update an existing model with new data
    bool updateModel(const std::string& name, const std::string& newData);

    // Get performance info for a model
    [[nodiscard]] ModelInfo getPerformance(const std::string& name) const;

    // Detect drift in a model based on recent prediction distributions
    [[nodiscard]] double detectDrift(const std::string& name,
                                     const std::vector<std::vector<double>>& recentPredictions) const;

    // Record a prediction for tracking purposes
    void recordPrediction(const std::string& name, const std::vector<double>& prediction);

    // Get the number of loaded models
    [[nodiscard]] size_t getModelCount() const;

    // Check if a model is loaded
    [[nodiscard]] bool isModelLoaded(const std::string& name) const;

private:
    mutable std::mutex mutex_;
    Core::ModuleLogger logger_;

    // Internal record for each managed model
    struct ManagedModel {
        std::unique_ptr<IMLModel> model;
        ModelInfo info;
        std::vector<std::vector<double>> predictionHistory;
    };

    std::unordered_map<std::string, ManagedModel> models_;

    // Drift detection helper: chi-squared divergence approximation
    [[nodiscard]] double computeDistributionDivergence(
        const std::vector<std::vector<double>>& historical,
        const std::vector<std::vector<double>>& recent) const;
};

} // namespace ThreatOne::AI
