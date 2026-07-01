#include "scanner/ScanHistory.h"

namespace ThreatOne::Scanner {

ScanHistory::ScanHistory(Database::ConnectionManager& connManager)
    : connManager_(connManager)
    , logger_(Core::Logger::instance().getModuleLogger("ScanHistory")) {
}

Core::Result<void, Core::Error> ScanHistory::recordScan(const ScanHistoryRecord& record) {
    auto connResult = connManager_.getConnection();
    if (connResult.isErr()) {
        return Core::Result<void, Core::Error>::err(connResult.error());
    }

    auto& conn = *connResult.value();

    Database::Models::Scan scan;
    scan.setType(record.type);
    scan.setStatus(record.status);
    scan.setTarget(record.target);
    scan.setStartedAt(record.startedAt);
    scan.setFindingsCount(static_cast<int>(record.threatsFound));

    auto result = Database::Models::Scan::create(conn, scan);
    if (result.isErr()) {
        logger_.error("Failed to record scan: {}", result.error().message());
        return Core::Result<void, Core::Error>::err(result.error());
    }

    logger_.debug("Recorded scan: {} type={}", record.scanId, record.type);
    return Core::Result<void, Core::Error>::ok();
}

Core::Result<void, Core::Error> ScanHistory::updateScan(const ScanHistoryRecord& record) {
    auto connResult = connManager_.getConnection();
    if (connResult.isErr()) {
        return Core::Result<void, Core::Error>::err(connResult.error());
    }

    auto& conn = *connResult.value();

    // Find scan by target (using scan ID stored in target field as identifier)
    auto scanResults = Database::Models::Scan::findWhere(
        conn, "target", Database::BoundParam::text(record.target));

    if (scanResults.isErr()) {
        return Core::Result<void, Core::Error>::err(scanResults.error());
    }

    if (!scanResults.value().empty()) {
        auto& scan = scanResults.value()[0];
        scan.setStatus(record.status);
        scan.setCompletedAt(record.completedAt);
        scan.setFindingsCount(static_cast<int>(record.threatsFound));
        auto updateResult = scan.update(conn);
        if (updateResult.isErr()) {
            return Core::Result<void, Core::Error>::err(updateResult.error());
        }
    }

    return Core::Result<void, Core::Error>::ok();
}

Core::Result<void, Core::Error> ScanHistory::recordThreat(const ThreatRecord& threat) {
    auto connResult = connManager_.getConnection();
    if (connResult.isErr()) {
        return Core::Result<void, Core::Error>::err(connResult.error());
    }

    auto& conn = *connResult.value();

    Database::Models::Threat threatModel;
    threatModel.setName(threat.name);
    threatModel.setSeverity(threat.severity);
    threatModel.setCategory(threat.category);
    threatModel.setSource(threat.source);
    threatModel.setFirstSeen(threat.firstSeen);
    threatModel.setStatus(threat.status);

    auto result = Database::Models::Threat::create(conn, threatModel);
    if (result.isErr()) {
        logger_.error("Failed to record threat: {}", result.error().message());
        return Core::Result<void, Core::Error>::err(result.error());
    }

    return Core::Result<void, Core::Error>::ok();
}

Core::Result<std::vector<ScanHistoryRecord>, Core::Error> ScanHistory::getRecentScans(int limit) {
    auto connResult = connManager_.getConnection();
    if (connResult.isErr()) {
        return Core::Result<std::vector<ScanHistoryRecord>, Core::Error>::err(connResult.error());
    }

    auto& conn = *connResult.value();
    auto scansResult = Database::Models::Scan::findAll(conn, limit);
    if (scansResult.isErr()) {
        return Core::Result<std::vector<ScanHistoryRecord>, Core::Error>::err(scansResult.error());
    }

    std::vector<ScanHistoryRecord> records;
    records.reserve(scansResult.value().size());
    for (const auto& scan : scansResult.value()) {
        ScanHistoryRecord record;
        record.type = scan.type();
        record.status = scan.status();
        record.target = scan.target();
        record.startedAt = scan.startedAt();
        record.completedAt = scan.completedAt();
        record.threatsFound = static_cast<uint64_t>(scan.findingsCount());
        records.push_back(std::move(record));
    }

    return Core::Result<std::vector<ScanHistoryRecord>, Core::Error>::ok(std::move(records));
}

Core::Result<ScanHistoryRecord, Core::Error> ScanHistory::getScanById(const std::string& scanId) {
    auto connResult = connManager_.getConnection();
    if (connResult.isErr()) {
        return Core::Result<ScanHistoryRecord, Core::Error>::err(connResult.error());
    }

    auto& conn = *connResult.value();
    auto scansResult = Database::Models::Scan::findWhere(
        conn, "target", Database::BoundParam::text(scanId));

    if (scansResult.isErr()) {
        return Core::Result<ScanHistoryRecord, Core::Error>::err(scansResult.error());
    }

    if (scansResult.value().empty()) {
        return Core::Result<ScanHistoryRecord, Core::Error>::err(
            Core::Error("Scan not found: " + scanId, Core::ErrorCategory::Validation));
    }

    const auto& scan = scansResult.value()[0];
    ScanHistoryRecord record;
    record.scanId = scanId;
    record.type = scan.type();
    record.status = scan.status();
    record.target = scan.target();
    record.startedAt = scan.startedAt();
    record.completedAt = scan.completedAt();
    record.threatsFound = static_cast<uint64_t>(scan.findingsCount());

    return Core::Result<ScanHistoryRecord, Core::Error>::ok(record);
}

} // namespace ThreatOne::Scanner
