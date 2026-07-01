#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace ThreatOne::EDR {

struct ProcessInfo {
    uint64_t pid = 0;
    std::string name;
    std::string path;
    std::string user;
    uint64_t parentPid = 0;
    std::string commandLine;
};

struct FileEvent {
    std::string path;
    std::string action;
    std::string processName;
    uint64_t pid = 0;
    std::string timestamp;
};

struct RegistryEvent {
    std::string key;
    std::string action;
    std::string value;
    std::string processName;
    std::string timestamp;
};

struct PersistenceIndicator {
    std::string type;
    std::string location;
    std::string description;
    std::string severity;
};

struct LateralMovementIndicator {
    std::string sourceHost;
    std::string destHost;
    std::string technique;
    std::string timestamp;
};

struct RansomwareIndicator {
    std::string indicator;
    std::string confidence;
    std::vector<std::string> affectedPaths;
};

class IEDREngine {
public:
    virtual ~IEDREngine() = default;

    virtual bool startCollection() = 0;
    virtual std::vector<ProcessInfo> getProcesses() = 0;
    virtual std::vector<FileEvent> getFileEvents() = 0;
    virtual std::vector<RegistryEvent> getRegistryEvents() = 0;
    virtual std::vector<PersistenceIndicator> detectPersistence() = 0;
    virtual std::vector<LateralMovementIndicator> detectLateralMovement() = 0;
    virtual std::vector<RansomwareIndicator> detectRansomware() = 0;
};

} // namespace ThreatOne::EDR
