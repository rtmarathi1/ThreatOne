#pragma once

#include <string>
#include <vector>

namespace ThreatOne::Updates {

struct UpdateInfo {
    std::string version;
    std::string description;
    std::string releaseDate;
    uint64_t size = 0;
    bool critical = false;
};

struct VersionInfo {
    std::string current;
    std::string latest;
    bool updateAvailable = false;
};

class IUpdateManager {
public:
    virtual ~IUpdateManager() = default;

    virtual std::vector<UpdateInfo> checkForUpdates() = 0;
    virtual bool downloadUpdate(const std::string& version) = 0;
    virtual bool installUpdate(const std::string& version) = 0;
    virtual VersionInfo getVersion() = 0;
    virtual bool rollback() = 0;
};

} // namespace ThreatOne::Updates
