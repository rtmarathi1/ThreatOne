#include <doctest/doctest.h>
#include <cloud/RemoteScanService.h>

using namespace ThreatOne::Cloud;

TEST_CASE("RemoteScanService - Initiate scan") {
    RemoteScanService svc;

    std::string id = svc.initiateScan("DEV-001", RemoteScanType::Quick);
    CHECK_FALSE(id.empty());
    CHECK(id.find("RSCAN-") == 0);

    auto result = svc.getScanResult(id);
    CHECK(result.deviceId == "DEV-001");
    CHECK(result.status == RemoteScanStatus::Running);
}

TEST_CASE("RemoteScanService - Complete scan") {
    RemoteScanService svc;

    std::string id = svc.initiateScan("DEV-001", RemoteScanType::Full);
    CHECK(svc.completeScan(id, 3, 1000, {"malware.exe", "trojan.dll", "backdoor.sys"}));

    auto result = svc.getScanResult(id);
    CHECK(result.status == RemoteScanStatus::Completed);
    CHECK(result.threatsFound == 3);
    CHECK(result.filesScanned == 1000);
    CHECK(result.findings.size() == 3);
}

TEST_CASE("RemoteScanService - Cancel scan") {
    RemoteScanService svc;

    std::string id = svc.initiateScan("DEV-002", RemoteScanType::Quick);
    CHECK(svc.cancelScan(id));

    auto result = svc.getScanResult(id);
    CHECK(result.status == RemoteScanStatus::Cancelled);
}

TEST_CASE("RemoteScanService - Cancel nonexistent scan fails") {
    RemoteScanService svc;
    CHECK_FALSE(svc.cancelScan("nonexistent"));
}

TEST_CASE("RemoteScanService - Cancel completed scan fails") {
    RemoteScanService svc;

    std::string id = svc.initiateScan("DEV-001", RemoteScanType::Quick);
    svc.completeScan(id, 0, 100, {});
    CHECK_FALSE(svc.cancelScan(id));
}

TEST_CASE("RemoteScanService - Get scans by device") {
    RemoteScanService svc;

    svc.initiateScan("DEV-001", RemoteScanType::Quick);
    svc.initiateScan("DEV-001", RemoteScanType::Full);
    svc.initiateScan("DEV-002", RemoteScanType::Quick);

    auto scans = svc.getScansByDevice("DEV-001");
    CHECK(scans.size() == 2);
}

TEST_CASE("RemoteScanService - Active scans list") {
    RemoteScanService svc;

    std::string id1 = svc.initiateScan("DEV-001", RemoteScanType::Quick);
    svc.initiateScan("DEV-002", RemoteScanType::Quick);
    svc.completeScan(id1, 0, 50, {});

    auto active = svc.getActiveScansList();
    CHECK(active.size() == 1);
    CHECK(svc.getActiveScanCount() == 1);
}

TEST_CASE("RemoteScanService - Batch scan") {
    RemoteScanService svc;

    std::vector<std::string> devices = {"DEV-001", "DEV-002", "DEV-003"};
    std::string batchId = svc.initiateBatchScan(devices, RemoteScanType::IOCSweep);
    CHECK_FALSE(batchId.empty());
    CHECK(svc.getActiveScanCount() == 3);
}

TEST_CASE("RemoteScanService - Aggregated results") {
    RemoteScanService svc;

    std::string id1 = svc.initiateScan("DEV-001", RemoteScanType::Quick);
    std::string id2 = svc.initiateScan("DEV-002", RemoteScanType::Full);
    svc.completeScan(id1, 2, 100, {"threat1", "threat2"});
    svc.completeScan(id2, 1, 200, {"threat3"});

    auto agg = svc.getAggregatedResults();
    CHECK(agg.totalScans == 2);
    CHECK(agg.completedScans == 2);
    CHECK(agg.totalThreats == 3);
    CHECK(agg.totalFilesScanned == 300);
}
