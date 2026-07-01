#pragma once

#include <string>
#include <vector>

namespace ThreatOne::HIDS {

struct IntegrityEvent {
    std::string id;
    std::string path;
    std::string changeType;
    std::string previousHash;
    std::string currentHash;
    std::string timestamp;
};

struct FileChange {
    std::string path;
    std::string action;
    std::string user;
    uint64_t size = 0;
    std::string timestamp;
};

struct PolicyViolation {
    std::string id;
    std::string policyName;
    std::string description;
    std::string severity;
    std::string path;
    std::string timestamp;
};

struct BaselineInfo {
    std::string id;
    std::string name;
    std::string createdAt;
    uint64_t fileCount = 0;
    std::string status;
};

class IHIDSEngine {
public:
    virtual ~IHIDSEngine() = default;

    virtual bool startMonitoring() = 0;
    virtual std::vector<IntegrityEvent> getIntegrityEvents() = 0;
    virtual std::vector<FileChange> getFileChanges() = 0;
    virtual std::vector<PolicyViolation> getPolicyViolations() = 0;
    virtual BaselineInfo getBaseline() = 0;
};

} // namespace ThreatOne::HIDS
