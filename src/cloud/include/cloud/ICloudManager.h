#pragma once

#include <string>
#include <vector>

namespace ThreatOne::Cloud {

struct CloudStatus {
    bool connected = false;
    std::string lastSync;
    std::string accountId;
    uint64_t storageUsed = 0;
    uint64_t storageTotal = 0;
};

struct BackupInfo {
    std::string id;
    std::string name;
    std::string timestamp;
    uint64_t size = 0;
};

class ICloudManager {
public:
    virtual ~ICloudManager() = default;

    virtual bool sync() = 0;
    virtual bool backup(const std::string& name) = 0;
    virtual bool restore(const std::string& backupId) = 0;
    virtual CloudStatus getStatus() = 0;
    virtual bool uploadThreatIntel(const std::string& data) = 0;
    virtual std::string downloadPolicies() = 0;
};

} // namespace ThreatOne::Cloud
