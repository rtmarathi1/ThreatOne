#include "scanner/ScanEngine.h"

namespace ThreatOne::Scanner {

ScanEngine::ScanEngine()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("ScanEngine")) {
    logger_.info("ScanEngine initialized (stub)");
}

std::string ScanEngine::startScan(const ScanConfig& config) {
    logger_.info("startScan called, type={}", static_cast<int>(config.type));
    return "SCAN-001";
}

bool ScanEngine::stopScan(const std::string& scanId) {
    logger_.info("stopScan called: {}", scanId);
    return true;
}

bool ScanEngine::pauseScan(const std::string& scanId) {
    logger_.info("pauseScan called: {}", scanId);
    return true;
}

ScanResult ScanEngine::getScanStatus(const std::string& scanId) {
    logger_.info("getScanStatus called: {}", scanId);
    return {scanId, ScanStatus::Idle, 0, 0, 0.0, {}};
}

std::vector<ScanResult> ScanEngine::getScanResults() {
    logger_.info("getScanResults called");
    return {};
}

} // namespace ThreatOne::Scanner
