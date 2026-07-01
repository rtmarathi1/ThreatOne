#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace ThreatOne::Scanner {

enum class ScanType {
    Quick,
    Full,
    Custom,
    Memory,
    Rootkit,
    Boot,
    Firmware,
    Registry,
    Startup,
    USB,
    Network,
    Cloud,
    Container,
    VM,
    IOC,
    YARA,
    Scheduled
};

enum class ScanStatus {
    Idle,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled
};

struct ScanConfig {
    ScanType type = ScanType::Quick;
    std::vector<std::string> targets;
    std::vector<std::string> exclusions;
    std::string schedule;
};

struct ScanResult {
    std::string scanId;
    ScanStatus status = ScanStatus::Idle;
    uint64_t filesScanned = 0;
    uint64_t threatsFound = 0;
    double progress = 0.0;
    std::vector<std::string> findings;
};

class IScanEngine {
public:
    virtual ~IScanEngine() = default;

    virtual std::string startScan(const ScanConfig& config) = 0;
    virtual bool stopScan(const std::string& scanId) = 0;
    virtual bool pauseScan(const std::string& scanId) = 0;
    virtual ScanResult getScanStatus(const std::string& scanId) = 0;
    virtual std::vector<ScanResult> getScanResults() = 0;
};

} // namespace ThreatOne::Scanner
