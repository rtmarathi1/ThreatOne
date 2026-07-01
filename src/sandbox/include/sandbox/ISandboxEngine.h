#pragma once

#include <string>
#include <vector>

namespace ThreatOne::Sandbox {

struct AnalysisResult {
    std::string id;
    std::string sampleHash;
    std::string verdict;
    double score = 0.0;
    std::vector<std::string> behaviors;
    std::string timestamp;
};

struct IOCInfo {
    std::string type;
    std::string value;
    std::string description;
    std::string confidence;
};

struct BehaviorReport {
    std::string sampleId;
    std::vector<std::string> processesCreated;
    std::vector<std::string> filesModified;
    std::vector<std::string> registryChanges;
    std::vector<std::string> networkConnections;
    std::vector<std::string> droppedFiles;
};

class ISandboxEngine {
public:
    virtual ~ISandboxEngine() = default;

    virtual std::string submitSample(const std::string& filePath) = 0;
    virtual AnalysisResult getAnalysis(const std::string& sampleId) = 0;
    virtual std::vector<IOCInfo> getIOCs(const std::string& sampleId) = 0;
    virtual BehaviorReport getBehaviorReport(const std::string& sampleId) = 0;
    virtual std::string detonateURL(const std::string& url) = 0;
};

} // namespace ThreatOne::Sandbox
