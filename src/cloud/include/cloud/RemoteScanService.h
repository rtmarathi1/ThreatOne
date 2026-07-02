#pragma once

#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>
#include <cstdint>

namespace ThreatOne::Cloud {

enum class RemoteScanStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled
};

enum class RemoteScanType {
    Quick,
    Full,
    Custom,
    IOCSweep
};

struct RemoteScanResult {
    std::string scanId;
    std::string deviceId;
    RemoteScanStatus status = RemoteScanStatus::Pending;
    RemoteScanType scanType = RemoteScanType::Quick;
    int threatsFound = 0;
    int filesScanned = 0;
    std::string startedAt;
    std::string completedAt;
    std::vector<std::string> findings;
};

struct AggregatedScanResults {
    int totalScans = 0;
    int completedScans = 0;
    int failedScans = 0;
    int totalThreats = 0;
    int totalFilesScanned = 0;
};

class RemoteScanService {
public:
    RemoteScanService();
    ~RemoteScanService() = default;

    // Scan initiation
    std::string initiateScan(const std::string& deviceId, RemoteScanType type);
    std::string initiateBatchScan(const std::vector<std::string>& deviceIds, RemoteScanType type);

    // Scan tracking
    [[nodiscard]] RemoteScanResult getScanResult(const std::string& scanId) const;
    [[nodiscard]] std::vector<RemoteScanResult> getScansByDevice(const std::string& deviceId) const;
    [[nodiscard]] std::vector<RemoteScanResult> getActiveScansList() const;

    // Scan control
    bool cancelScan(const std::string& scanId);
    bool completeScan(const std::string& scanId, int threatsFound, int filesScanned,
                      const std::vector<std::string>& findings);

    // Aggregation
    [[nodiscard]] AggregatedScanResults getAggregatedResults() const;
    [[nodiscard]] size_t getActiveScanCount() const;

private:
    std::string generateScanId();

    mutable std::mutex mutex_;
    std::map<std::string, RemoteScanResult> scans_;
    std::map<std::string, std::vector<std::string>> scansByDevice_;
    int nextScanId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Cloud
