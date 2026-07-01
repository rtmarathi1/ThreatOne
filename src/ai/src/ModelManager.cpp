#include "ai/ModelManager.h"
#include "ai/DecisionTreeClassifier.h"

#include <algorithm>
#include <cmath>
#include <numeric>
#include <sstream>

namespace ThreatOne::AI {

ModelManager::ModelManager()
    : logger_(Core::Logger::instance().getModuleLogger("ModelManager"))
{
    logger_.info("ModelManager initialized");
}

bool ModelManager::loadModel(const std::string& name, const std::string& modelData) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Create a new decision tree model instance
    auto model = std::make_unique<DecisionTreeClassifier>();
    if (!model->load(modelData)) {
        logger_.error("Failed to load model: {}", name);
        return false;
    }

    ManagedModel managed;
    managed.info.id = name;
    managed.info.name = model->getName();
    managed.info.version = model->getVersion();
    managed.info.type = "DecisionTree";
    managed.info.status = ModelStatus::Loaded;
    managed.info.accuracy = model->getMetadata().accuracy;
    managed.info.loadTime = std::chrono::steady_clock::now();
    managed.info.predictionCount = 0;
    managed.info.driftScore = 0.0;
    managed.model = std::move(model);

    models_[name] = std::move(managed);

    logger_.info("Model loaded: {} (version {})", name, models_[name].info.version);
    return true;
}

bool ModelManager::unloadModel(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = models_.find(name);
    if (it == models_.end()) {
        logger_.warn("Cannot unload model '{}': not found", name);
        return false;
    }

    it->second.info.status = ModelStatus::Unloaded;
    it->second.model.reset();
    models_.erase(it);

    logger_.info("Model unloaded: {}", name);
    return true;
}

IMLModel* ModelManager::getModel(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = models_.find(name);
    if (it == models_.end() || !it->second.model) {
        return nullptr;
    }
    return it->second.model.get();
}

std::vector<ModelInfo> ModelManager::listModels() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ModelInfo> result;
    result.reserve(models_.size());
    for (const auto& [name, managed] : models_) {
        result.push_back(managed.info);
    }
    return result;
}

bool ModelManager::updateModel(const std::string& name, const std::string& newData) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = models_.find(name);
    if (it == models_.end()) {
        logger_.warn("Cannot update model '{}': not found", name);
        return false;
    }

    it->second.info.status = ModelStatus::Updating;

    auto newModel = std::make_unique<DecisionTreeClassifier>();
    if (!newModel->load(newData)) {
        it->second.info.status = ModelStatus::Error;
        logger_.error("Failed to update model: {}", name);
        return false;
    }

    it->second.model = std::move(newModel);
    it->second.info.version = it->second.model->getVersion();
    it->second.info.status = ModelStatus::Loaded;
    it->second.info.accuracy = it->second.model->getMetadata().accuracy;

    logger_.info("Model updated: {} (new version {})", name, it->second.info.version);
    return true;
}

ModelInfo ModelManager::getPerformance(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = models_.find(name);
    if (it == models_.end()) {
        return ModelInfo{};
    }
    return it->second.info;
}

double ModelManager::detectDrift(const std::string& name,
                                  const std::vector<std::vector<double>>& recentPredictions) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = models_.find(name);
    if (it == models_.end() || it->second.predictionHistory.empty()) {
        return 0.0;
    }

    double drift = computeDistributionDivergence(it->second.predictionHistory, recentPredictions);
    logger_.debug("Drift score for model '{}': {:.4f}", name, drift);
    return drift;
}

void ModelManager::recordPrediction(const std::string& name, const std::vector<double>& prediction) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = models_.find(name);
    if (it == models_.end()) {
        return;
    }

    it->second.predictionHistory.push_back(prediction);
    it->second.info.predictionCount++;

    // Keep history bounded (last 1000 predictions)
    const size_t maxHistory = 1000;
    if (it->second.predictionHistory.size() > maxHistory) {
        it->second.predictionHistory.erase(
            it->second.predictionHistory.begin(),
            it->second.predictionHistory.begin() +
                static_cast<std::ptrdiff_t>(it->second.predictionHistory.size() - maxHistory));
    }
}

size_t ModelManager::getModelCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return models_.size();
}

bool ModelManager::isModelLoaded(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = models_.find(name);
    return it != models_.end() && it->second.model != nullptr;
}

double ModelManager::computeDistributionDivergence(
    const std::vector<std::vector<double>>& historical,
    const std::vector<std::vector<double>>& recent) const {

    if (historical.empty() || recent.empty()) {
        return 0.0;
    }

    // Compute mean predictions for historical and recent
    size_t dimensions = historical[0].size();
    if (dimensions == 0) return 0.0;

    std::vector<double> histMean(dimensions, 0.0);
    std::vector<double> recentMean(dimensions, 0.0);

    for (const auto& pred : historical) {
        for (size_t i = 0; i < std::min(dimensions, pred.size()); ++i) {
            histMean[i] += pred[i];
        }
    }
    for (auto& v : histMean) {
        v /= static_cast<double>(historical.size());
    }

    for (const auto& pred : recent) {
        for (size_t i = 0; i < std::min(dimensions, pred.size()); ++i) {
            recentMean[i] += pred[i];
        }
    }
    for (auto& v : recentMean) {
        v /= static_cast<double>(recent.size());
    }

    // Chi-squared divergence approximation
    double chiSquared = 0.0;
    for (size_t i = 0; i < dimensions; ++i) {
        double expected = histMean[i] + 1e-10; // Avoid division by zero
        double diff = recentMean[i] - histMean[i];
        chiSquared += (diff * diff) / std::abs(expected);
    }

    // Normalize to [0, 1] range using sigmoid-like function
    return 1.0 - (1.0 / (1.0 + chiSquared));
}

} // namespace ThreatOne::AI
