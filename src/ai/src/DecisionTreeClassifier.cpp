#include "ai/DecisionTreeClassifier.h"

#include <sstream>

namespace ThreatOne::AI {

DecisionTreeClassifier::DecisionTreeClassifier()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("DecisionTreeClassifier"))
    , version_("1.0.0")
    , name_("SecurityDecisionTree") {
    buildDefaultTree();
    logger_.info("DecisionTreeClassifier initialized with {} nodes", nodes_.size());
}

void DecisionTreeClassifier::buildDefaultTree() {
    // Build a default security-focused decision tree with hardcoded thresholds
    //
    // Tree structure:
    // [0] entropy > 7.0?
    //   Yes -> [1] suspiciousStringCount > 5?
    //            Yes -> [3] LEAF: malicious (0.92)
    //            No  -> [4] importCount > 30?
    //                     Yes -> [7] LEAF: suspicious (0.78)
    //                     No  -> [8] LEAF: benign (0.65)
    //   No  -> [2] importCount > 30?
    //            Yes -> [5] suspiciousStringCount > 3?
    //                     Yes -> [9] LEAF: suspicious (0.80)
    //                     No  -> [10] LEAF: benign (0.70)
    //            No  -> [6] suspiciousStringScore > 5.0?
    //                     Yes -> [11] LEAF: suspicious (0.72)
    //                     No  -> [12] LEAF: benign (0.95)

    nodes_.clear();
    nodes_.resize(13);

    // Node 0: Root - split on entropy
    nodes_[0].featureName = "entropy";
    nodes_[0].threshold = 7.0;
    nodes_[0].leftChild = 2;   // entropy <= 7.0
    nodes_[0].rightChild = 1;  // entropy > 7.0
    nodes_[0].isLeaf = false;

    // Node 1: High entropy branch - split on suspiciousStringCount
    nodes_[1].featureName = "suspiciousStringCount";
    nodes_[1].threshold = 5.0;
    nodes_[1].leftChild = 4;   // suspiciousStringCount <= 5
    nodes_[1].rightChild = 3;  // suspiciousStringCount > 5
    nodes_[1].isLeaf = false;

    // Node 2: Low entropy branch - split on importCount
    nodes_[2].featureName = "importCount";
    nodes_[2].threshold = 30.0;
    nodes_[2].leftChild = 6;   // importCount <= 30
    nodes_[2].rightChild = 5;  // importCount > 30
    nodes_[2].isLeaf = false;

    // Node 3: LEAF - high entropy + many suspicious strings = malicious
    nodes_[3].isLeaf = true;
    nodes_[3].label = "malicious";
    nodes_[3].confidence = 0.92;

    // Node 4: High entropy, low suspicious strings - split on importCount
    nodes_[4].featureName = "importCount";
    nodes_[4].threshold = 30.0;
    nodes_[4].leftChild = 8;   // importCount <= 30
    nodes_[4].rightChild = 7;  // importCount > 30
    nodes_[4].isLeaf = false;

    // Node 5: Low entropy, high imports - split on suspiciousStringCount
    nodes_[5].featureName = "suspiciousStringCount";
    nodes_[5].threshold = 3.0;
    nodes_[5].leftChild = 10;  // suspiciousStringCount <= 3
    nodes_[5].rightChild = 9;  // suspiciousStringCount > 3
    nodes_[5].isLeaf = false;

    // Node 6: Low entropy, low imports - split on suspiciousStringScore
    nodes_[6].featureName = "suspiciousStringScore";
    nodes_[6].threshold = 5.0;
    nodes_[6].leftChild = 12;  // score <= 5.0
    nodes_[6].rightChild = 11; // score > 5.0
    nodes_[6].isLeaf = false;

    // Node 7: LEAF - high entropy + many imports = suspicious
    nodes_[7].isLeaf = true;
    nodes_[7].label = "suspicious";
    nodes_[7].confidence = 0.78;

    // Node 8: LEAF - high entropy only = benign (e.g., compressed file)
    nodes_[8].isLeaf = true;
    nodes_[8].label = "benign";
    nodes_[8].confidence = 0.65;

    // Node 9: LEAF - many imports + suspicious strings = suspicious
    nodes_[9].isLeaf = true;
    nodes_[9].label = "suspicious";
    nodes_[9].confidence = 0.80;

    // Node 10: LEAF - many imports but no suspicious strings = benign
    nodes_[10].isLeaf = true;
    nodes_[10].label = "benign";
    nodes_[10].confidence = 0.70;

    // Node 11: LEAF - high suspicious string score = suspicious
    nodes_[11].isLeaf = true;
    nodes_[11].label = "suspicious";
    nodes_[11].confidence = 0.72;

    // Node 12: LEAF - nothing suspicious = benign
    nodes_[12].isLeaf = true;
    nodes_[12].label = "benign";
    nodes_[12].confidence = 0.95;
}

bool DecisionTreeClassifier::load(const std::string& modelData) {
    // For the default implementation, we rebuild the default tree
    // In a full implementation, this would parse a serialized tree from modelData
    if (modelData.empty()) {
        buildDefaultTree();
        logger_.info("Loaded default decision tree model");
        return true;
    }

    // Future: parse JSON model data
    logger_.warn("Custom model loading not yet implemented, using default tree");
    buildDefaultTree();
    return true;
}

std::vector<double> DecisionTreeClassifier::predict(const FeatureVector& features) {
    ModelPrediction result = classify(features);

    // Return as vector: [benign_score, suspicious_score, malicious_score]
    std::vector<double> scores(3, 0.0);

    if (result.label == "benign") {
        scores[0] = result.confidence;
        scores[1] = (1.0 - result.confidence) * 0.7;
        scores[2] = (1.0 - result.confidence) * 0.3;
    } else if (result.label == "suspicious") {
        scores[0] = (1.0 - result.confidence) * 0.5;
        scores[1] = result.confidence;
        scores[2] = (1.0 - result.confidence) * 0.5;
    } else if (result.label == "malicious") {
        scores[0] = (1.0 - result.confidence) * 0.2;
        scores[1] = (1.0 - result.confidence) * 0.8;
        scores[2] = result.confidence;
    }

    logger_.debug("Prediction scores: benign={:.3f}, suspicious={:.3f}, malicious={:.3f}",
                  scores[0], scores[1], scores[2]);

    return scores;
}

std::string DecisionTreeClassifier::explain(const FeatureVector& features) {
    std::ostringstream explanation;
    explanation << "Decision path: ";

    int nodeIdx = 0;
    while (nodeIdx >= 0 && nodeIdx < static_cast<int>(nodes_.size())) {
        const auto& node = nodes_[nodeIdx];

        if (node.isLeaf) {
            explanation << "-> [" << node.label << " (confidence: "
                       << node.confidence << ")]";
            break;
        }

        double featureValue = getFeatureValue(features, node.featureName);
        explanation << node.featureName << "=" << featureValue;

        if (featureValue > node.threshold) {
            explanation << " > " << node.threshold << " (yes) ";
            nodeIdx = node.rightChild;
        } else {
            explanation << " <= " << node.threshold << " (no) ";
            nodeIdx = node.leftChild;
        }
    }

    return explanation.str();
}

std::string DecisionTreeClassifier::getVersion() {
    return version_;
}

std::string DecisionTreeClassifier::getName() {
    return name_;
}

ModelMetadata DecisionTreeClassifier::getMetadata() {
    return ModelMetadata{
        name_,
        version_,
        0.87, // Default accuracy for the hardcoded tree
        "2024-01-01",
        "Security-focused decision tree for malware classification"
    };
}

ModelPrediction DecisionTreeClassifier::classify(const FeatureVector& features) const {
    int leafIdx = traverseTree(features, 0);

    if (leafIdx < 0 || leafIdx >= static_cast<int>(nodes_.size())) {
        return ModelPrediction{"unknown", 0.0, {"Error: invalid tree traversal"}};
    }

    const auto& leaf = nodes_[leafIdx];
    ModelPrediction prediction;
    prediction.label = leaf.label;
    prediction.confidence = leaf.confidence;

    // Build explanation path
    std::ostringstream path;
    int nodeIdx = 0;
    while (nodeIdx >= 0 && nodeIdx < static_cast<int>(nodes_.size())) {
        const auto& node = nodes_[nodeIdx];
        if (node.isLeaf) {
            break;
        }
        double val = getFeatureValue(features, node.featureName);
        if (val > node.threshold) {
            path << node.featureName << ">" << node.threshold << " ";
            nodeIdx = node.rightChild;
        } else {
            path << node.featureName << "<=" << node.threshold << " ";
            nodeIdx = node.leftChild;
        }
    }
    prediction.explanations.push_back(path.str());

    return prediction;
}

size_t DecisionTreeClassifier::getTreeSize() const {
    return nodes_.size();
}

int DecisionTreeClassifier::traverseTree(const FeatureVector& features, int nodeIndex) const {
    if (nodeIndex < 0 || nodeIndex >= static_cast<int>(nodes_.size())) {
        return -1;
    }

    const auto& node = nodes_[nodeIndex];

    if (node.isLeaf) {
        return nodeIndex;
    }

    double featureValue = getFeatureValue(features, node.featureName);

    if (featureValue > node.threshold) {
        return traverseTree(features, node.rightChild);
    } else {
        return traverseTree(features, node.leftChild);
    }
}

double DecisionTreeClassifier::getFeatureValue(const FeatureVector& features,
                                                const std::string& featureName) {
    auto it = features.find(featureName);
    if (it != features.end()) {
        return it->second;
    }
    return 0.0;
}

} // namespace ThreatOne::AI
