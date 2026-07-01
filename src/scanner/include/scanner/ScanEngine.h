#pragma once

#include "scanner/IScanEngine.h"
#include "core/Logger.h"

namespace ThreatOne::Scanner {

class ScanEngine : public IScanEngine {
public:
    ScanEngine();
    ~ScanEngine() override = default;

    std::string startScan(const ScanConfig& config) override;
    bool stopScan(const std::string& scanId) override;
    bool pauseScan(const std::string& scanId) override;
    ScanResult getScanStatus(const std::string& scanId) override;
    std::vector<ScanResult> getScanResults() override;

private:
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Scanner
