#include <doctest/doctest.h>
#include <hids/RootkitDetector.h>

using namespace ThreatOne::HIDS;

TEST_CASE("RootkitDetector - Run scan standard depth") {
    RootkitDetector detector;
    CHECK(detector.runScan(ScanDepth::Standard));

    auto result = detector.getLastScanResult();
    CHECK_FALSE(result.scanId.empty());
    CHECK(result.clean);
    CHECK(result.processesScanned > 0);
    CHECK(result.filesScanned > 0);
    CHECK(result.modulesChecked > 0);
}

TEST_CASE("RootkitDetector - Run scan quick depth") {
    RootkitDetector detector;
    CHECK(detector.runScan(ScanDepth::Quick));

    auto result = detector.getLastScanResult();
    CHECK(result.depth == ScanDepth::Quick);
    CHECK(result.indicators.size() == 2); // only process + file checks
}

TEST_CASE("RootkitDetector - Run scan deep depth") {
    RootkitDetector detector;
    CHECK(detector.runScan(ScanDepth::Deep));

    auto result = detector.getLastScanResult();
    CHECK(result.depth == ScanDepth::Deep);
    CHECK(result.indicators.size() == 4); // all checks
    CHECK(result.syscallsVerified > 0);
}

TEST_CASE("RootkitDetector - Get indicators after scan") {
    RootkitDetector detector;
    detector.runScan(ScanDepth::Deep);

    auto indicators = detector.getIndicators();
    CHECK(indicators.size() == 4);

    bool foundProcess = false;
    bool foundFile = false;
    bool foundKernel = false;
    bool foundSyscall = false;

    for (const auto& ind : indicators) {
        switch (ind.type) {
            case RootkitType::HiddenProcess: foundProcess = true; break;
            case RootkitType::HiddenFile: foundFile = true; break;
            case RootkitType::KernelModule: foundKernel = true; break;
            case RootkitType::SyscallHook: foundSyscall = true; break;
        }
    }

    CHECK(foundProcess);
    CHECK(foundFile);
    CHECK(foundKernel);
    CHECK(foundSyscall);
}

TEST_CASE("RootkitDetector - Scan clears previous indicators") {
    RootkitDetector detector;
    detector.runScan(ScanDepth::Deep);
    auto first = detector.getIndicators();

    detector.runScan(ScanDepth::Deep);
    auto second = detector.getIndicators();

    CHECK(first[0].id != second[0].id);
}

TEST_CASE("RootkitDetector - Signature management") {
    RootkitDetector detector;

    KnownRootkitSignature sig;
    sig.name = "TestRootkit";
    sig.type = RootkitType::KernelModule;
    sig.signature = "pattern123";
    sig.description = "Test signature";

    auto id = detector.addSignature(sig);
    CHECK_FALSE(id.empty());

    auto sigs = detector.getSignatures();
    CHECK(sigs.size() == 1);
    CHECK(sigs[0].name == "TestRootkit");

    CHECK(detector.removeSignature(id));
    CHECK_FALSE(detector.removeSignature("nonexistent"));
    CHECK(detector.getSignatures().empty());
}

TEST_CASE("RootkitDetector - Add signature with empty fields fails") {
    RootkitDetector detector;

    KnownRootkitSignature sig;
    sig.name = "";
    sig.signature = "test";
    CHECK(detector.addSignature(sig).empty());

    sig.name = "Test";
    sig.signature = "";
    CHECK(detector.addSignature(sig).empty());
}

TEST_CASE("RootkitDetector - Scanning state") {
    RootkitDetector detector;
    CHECK_FALSE(detector.isScanning());
}

TEST_CASE("RootkitDetector - Total scans counter") {
    RootkitDetector detector;
    CHECK(detector.getTotalScansPerformed() == 0);

    detector.runScan();
    CHECK(detector.getTotalScansPerformed() == 1);

    detector.runScan();
    CHECK(detector.getTotalScansPerformed() == 2);
}
