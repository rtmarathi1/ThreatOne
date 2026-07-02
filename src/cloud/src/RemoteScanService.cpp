#include "cloud/RemoteScanService.h"

#include <algorithm>

namespace ThreatOne::Cloud {

RemoteScanService::RemoteScanService()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("RemoteScanService")) {
    logger_.info("RemoteScanService initialized");
}

std::string RemoteScanService::generateScanId() {
    return "RSCAN-" + std::to_string(nextScanId_++);
}

std::string RemoteScanService::initiateScan(const std::string& deviceId, RemoteScanType type) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = generateScanId();
    RemoteScanResult result;
    result.scanId = id;
    result.deviceId = deviceId;
    result.status = RemoteScanStatus::Running;
    result.scanType = type;
    result.startedAt = "now";

    scans_[id] = result;
    scansByDevice_[deviceId].push_back(id);

    logger_.info("Initiated remote scan: id={}, device={}, type={}", id, deviceId, static_cast<int>(type));
    return id;
}

std::string RemoteScanService::initiateBatchScan(const std::vector<std::string>& deviceIds, RemoteScanType type) {
    // Generate a batch ID but create individual scans per device
    std::string batchId;
    for (const auto& deviceId : deviceIds) {
        std::string id = initiateScan(deviceId, type);
        if (batchId.empty()) {
            batchId = id;  // Return first scan ID as batch reference
        }
    }
    logger_.info("Initiated batch scan across {} devices", deviceIds.size());
    return batchId;
}

RemoteScanResult RemoteScanService::getScanResult(const std::string& scanId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = scans_.find(scanId);
    if (it == scans_.end()) {
        return {};
    }
    return it->second;
}

std::vector<RemoteScanResult> RemoteScanService::getScansByDevice(const std::string& deviceId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<RemoteScanResult> results;
    auto it = scansByDevice_.find(deviceId);
    if (it == scansByDevice_.end()) {
        return results;
    }

    for (const auto& scanId : it->second) {
        auto scanIt = scans_.find(scanId);
        if (scanIt != scans_.end()) {
            results.push_back(scanIt->second);
        }
    }
    return results;
}

std::vector<RemoteScanResult> RemoteScanService::getActiveScansList() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<RemoteScanResult> results;
    for (const auto& [id, scan] : scans_) {
        if (scan.status == RemoteScanStatus::Running || scan.status == RemoteScanStatus::Pending) {
            results.push_back(scan);
        }
    }
    return results;
}

bool RemoteScanService::cancelScan(const std::string& scanId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = scans_.find(scanId);
    if (it == scans_.end()) {
        logger_.warn("cancelScan: scan {} not found", scanId);
        return false;
    }

    if (it->second.status != RemoteScanStatus::Running && it->second.status != RemoteScanStatus::Pending) {
        logger_.warn("cancelScan: scan {} is not active", scanId);
        return false;
    }

    it->second.status = RemoteScanStatus::Cancelled;
    it->second.completedAt = "now";
    logger_.info("Cancelled scan: {}", scanId);
    return true;
}

bool RemoteScanService::completeScan(const std::string& scanId, int threatsFound, int filesScanned,
                                      const std::vector<std::string>& findings) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = scans_.find(scanId);
    if (it == scans_.end()) {
        logger_.warn("completeScan: scan {} not found", scanId);
        return false;
    }

    if (it->second.status != RemoteScanStatus::Running) {
        logger_.warn("completeScan: scan {} is not running", scanId);
        return false;
    }

    it->second.status = RemoteScanStatus::Completed;
    it->second.threatsFound = threatsFound;
    it->second.filesScanned = filesScanned;
    it->second.findings = findings;
    it->second.completedAt = "now";

    logger_.info("Completed scan: id={}, threats={}, files={}", scanId, threatsFound, filesScanned);
    return true;
}

AggregatedScanResults RemoteScanService::getAggregatedResults() const {
    std::lock_guard<std::mutex> lock(mutex_);

    AggregatedScanResults agg;
    agg.totalScans = static_cast<int>(scans_.size());

    for (const auto& [id, scan] : scans_) {
        if (scan.status == RemoteScanStatus::Completed) {
            agg.completedScans++;
            agg.totalThreats += scan.threatsFound;
            agg.totalFilesScanned += scan.filesScanned;
        } else if (scan.status == RemoteScanStatus::Failed) {
            agg.failedScans++;
        }
    }
    return agg;
}

size_t RemoteScanService::getActiveScanCount() const {
    std::lock_guard<std::mutex> lock(mutex_);

    size_t count = 0;
    for (const auto& [id, scan] : scans_) {
        if (scan.status == RemoteScanStatus::Running || scan.status == RemoteScanStatus::Pending) {
            count++;
        }
    }
    return count;
}

} // namespace ThreatOne::Cloud
