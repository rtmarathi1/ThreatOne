#pragma once

#include <string>
#include <vector>
#include <memory>

#include "ai/IMLModel.h"
#include "core/Logger.h"

namespace ThreatOne::AI {

// A single node in the decision tree
struct DecisionTreeNode {
    std::string featureName;          // Feature to split on (empty for leaf)
    double threshold = 0.0;           // Threshold value for the split
    int leftChild = -1;               // Index of left child (value <= threshold)
    int rightChild = -1;              // Index of right child (value > threshold)
    std::string label;                // Classification label (only for leaf nodes)
    double confidence = 0.0;          // Confidence of leaf classification
    bool isLeaf = false;
};

// Decision tree classifier implementing the IMLModel interface
class DecisionTreeClassifier : public IMLModel {
public:
    DecisionTreeClassifier();
    ~DecisionTreeClassifier() override = default;

    // IMLModel interface
    bool load(const std::string& modelData) override;
    std::vector<double> predict(const FeatureVector& features) override;
    std::string explain(const FeatureVector& features) override;
    std::string getVersion() override;
    std::string getName() override;
    ModelMetadata getMetadata() override;

    // Get the classification result with label and confidence
    [[nodiscard]] ModelPrediction classify(const FeatureVector& features) const;

    // Get current tree size (number of nodes)
    [[nodiscard]] size_t getTreeSize() const;

private:
    Core::ModuleLogger logger_;
    std::vector<DecisionTreeNode> nodes_;
    std::string version_;
    std::string name_;

    // Build the default security-focused decision tree
    void buildDefaultTree();

    // Traverse the tree for a given feature vector
    [[nodiscard]] int traverseTree(const FeatureVector& features, int nodeIndex) const;

    // Get the value of a feature, returning 0.0 if not found
    [[nodiscard]] static double getFeatureValue(const FeatureVector& features,
                                                 const std::string& featureName);
};

} // namespace ThreatOne::AI
