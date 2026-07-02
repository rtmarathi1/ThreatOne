#pragma once

// ThreatOne Scanner - Scan History
// Store scan results in the database using existing Model system

#include <string>
#include <vector>

#include <core/Error.h>
#include <core/Logger.h>
#include <database/ConnectionManager.h>
#include <database/models/Scan.h>
#include <database/models/Threat.h>
#include <cstdint>

namespace ThreatOne::Scanner {

// Scan history entry for recording scan results
struct ScanHistoryRecord {
    std::string scanId;
    std::string type;
    std::string status;
    std::string startedAt;
    std::string completedAt;
    uint64_t filesScanned = 0;
    uint64_t threatsFound = 0;
    std::string target;
};

// Threat finding record for individual threats found during a scan
struct ThreatRecord {
    std::string name;
    std::string severity;
    std::string category;
    std::string source;
    std::string firstSeen;
    std::string status;
};

// Manages scan history persistence
class ScanHistory {
public:
    explicit ScanHistory(Database::ConnectionManager& connManager);

    // Record a new scan
    Core::Result<void, Core::Error> recordScan(const ScanHistoryRecord& record);

    // Update scan status and results
    Core::Result<void, Core::Error> updateScan(const ScanHistoryRecord& record);

    // Record a threat finding
    Core::Result<void, Core::Error> recordThreat(const ThreatRecord& threat);

    // Get recent scans
    Core::Result<std::vector<ScanHistoryRecord>, Core::Error> getRecentScans(int limit = 10);

    // Get scan by ID
    Core::Result<ScanHistoryRecord, Core::Error> getScanById(const std::string& scanId);

private:
    Database::ConnectionManager& connManager_;
    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Scanner
