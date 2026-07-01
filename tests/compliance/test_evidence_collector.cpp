#include <doctest/doctest.h>
#include <compliance/EvidenceCollector.h>

using namespace ThreatOne::Compliance;

TEST_CASE("EvidenceCollector - add and retrieve evidence") {
    EvidenceCollector collector;

    auto result = collector.addEvidence(
        "NIST-ID-1", Framework::NIST, EvidenceType::ConfigFile,
        "Firewall Config", "firewall.conf contents");
    REQUIRE(result.isOk());

    auto record = result.value();
    CHECK_FALSE(record.id.empty());
    CHECK(record.controlId == "NIST-ID-1");
    CHECK(record.framework == Framework::NIST);
    CHECK(record.type == EvidenceType::ConfigFile);
    CHECK(record.title == "Firewall Config");
    CHECK(record.content == "firewall.conf contents");
    CHECK_FALSE(record.collectedAt.empty());
    CHECK(record.verified == false);
}

TEST_CASE("EvidenceCollector - get evidence by ID") {
    EvidenceCollector collector;

    auto result = collector.addEvidence(
        "CTRL-1", Framework::SOC2, EvidenceType::LogEntry,
        "Audit Log", "log entry data");
    REQUIRE(result.isOk());

    auto found = collector.getEvidence(result.value().id);
    REQUIRE(found.has_value());
    CHECK(found->title == "Audit Log");

    auto notFound = collector.getEvidence("nonexistent");
    CHECK_FALSE(notFound.has_value());
}

TEST_CASE("EvidenceCollector - get evidence for control") {
    EvidenceCollector collector;

    collector.addEvidence("CTRL-1", Framework::NIST, EvidenceType::ConfigFile, "Config A", "a");
    collector.addEvidence("CTRL-1", Framework::NIST, EvidenceType::LogEntry, "Log B", "b");
    collector.addEvidence("CTRL-2", Framework::NIST, EvidenceType::ScanResult, "Scan C", "c");

    auto ctrl1Evidence = collector.getEvidenceForControl("CTRL-1");
    CHECK(ctrl1Evidence.size() == 2);

    auto ctrl2Evidence = collector.getEvidenceForControl("CTRL-2");
    CHECK(ctrl2Evidence.size() == 1);
}

TEST_CASE("EvidenceCollector - get evidence by type") {
    EvidenceCollector collector;

    collector.addEvidence("C1", Framework::NIST, EvidenceType::ConfigFile, "T1", "d1");
    collector.addEvidence("C2", Framework::NIST, EvidenceType::ConfigFile, "T2", "d2");
    collector.addEvidence("C3", Framework::NIST, EvidenceType::LogEntry, "T3", "d3");

    auto configs = collector.getEvidenceByType(EvidenceType::ConfigFile);
    CHECK(configs.size() == 2);

    auto logs = collector.getEvidenceByType(EvidenceType::LogEntry);
    CHECK(logs.size() == 1);
}

TEST_CASE("EvidenceCollector - get evidence by framework") {
    EvidenceCollector collector;

    collector.addEvidence("C1", Framework::NIST, EvidenceType::ConfigFile, "T1", "d1");
    collector.addEvidence("C2", Framework::SOC2, EvidenceType::ConfigFile, "T2", "d2");
    collector.addEvidence("C3", Framework::NIST, EvidenceType::LogEntry, "T3", "d3");

    auto nistEvidence = collector.getEvidenceByFramework(Framework::NIST);
    CHECK(nistEvidence.size() == 2);

    auto socEvidence = collector.getEvidenceByFramework(Framework::SOC2);
    CHECK(socEvidence.size() == 1);
}

TEST_CASE("EvidenceCollector - verify evidence") {
    EvidenceCollector collector;

    auto result = collector.addEvidence(
        "C1", Framework::NIST, EvidenceType::PolicyDocument, "Policy", "doc");
    REQUIRE(result.isOk());

    auto id = result.value().id;
    CHECK(collector.getEvidence(id)->verified == false);

    auto verifyResult = collector.verifyEvidence(id);
    REQUIRE(verifyResult.isOk());
    CHECK(collector.getEvidence(id)->verified == true);
}

TEST_CASE("EvidenceCollector - verify nonexistent returns error") {
    EvidenceCollector collector;
    auto result = collector.verifyEvidence("nonexistent");
    REQUIRE(result.isErr());
}

TEST_CASE("EvidenceCollector - remove evidence") {
    EvidenceCollector collector;

    auto result = collector.addEvidence("C1", Framework::NIST, EvidenceType::ConfigFile, "T1", "d1");
    REQUIRE(result.isOk());

    CHECK(collector.getEvidenceCount() == 1);

    auto removeResult = collector.removeEvidence(result.value().id);
    REQUIRE(removeResult.isOk());
    CHECK(collector.getEvidenceCount() == 0);
}

TEST_CASE("EvidenceCollector - remove nonexistent returns error") {
    EvidenceCollector collector;
    auto result = collector.removeEvidence("nonexistent");
    REQUIRE(result.isErr());
}

TEST_CASE("EvidenceCollector - validation errors") {
    EvidenceCollector collector;

    SUBCASE("Empty control ID") {
        auto result = collector.addEvidence("", Framework::NIST, EvidenceType::ConfigFile, "T", "d");
        REQUIRE(result.isErr());
        CHECK(result.error().category() == ThreatOne::Core::ErrorCategory::Validation);
    }

    SUBCASE("Empty title") {
        auto result = collector.addEvidence("C1", Framework::NIST, EvidenceType::ConfigFile, "", "d");
        REQUIRE(result.isErr());
        CHECK(result.error().category() == ThreatOne::Core::ErrorCategory::Validation);
    }
}

TEST_CASE("EvidenceCollector - clear all") {
    EvidenceCollector collector;

    collector.addEvidence("C1", Framework::NIST, EvidenceType::ConfigFile, "T1", "d1");
    collector.addEvidence("C2", Framework::SOC2, EvidenceType::LogEntry, "T2", "d2");
    CHECK(collector.getEvidenceCount() == 2);

    collector.clearAll();
    CHECK(collector.getEvidenceCount() == 0);
}

TEST_CASE("EvidenceCollector - all evidence types supported") {
    EvidenceCollector collector;

    SUBCASE("ConfigFile") {
        auto r = collector.addEvidence("C1", Framework::NIST, EvidenceType::ConfigFile, "T", "d");
        REQUIRE(r.isOk());
        CHECK(r.value().type == EvidenceType::ConfigFile);
    }

    SUBCASE("LogEntry") {
        auto r = collector.addEvidence("C1", Framework::NIST, EvidenceType::LogEntry, "T", "d");
        REQUIRE(r.isOk());
        CHECK(r.value().type == EvidenceType::LogEntry);
    }

    SUBCASE("PolicyDocument") {
        auto r = collector.addEvidence("C1", Framework::NIST, EvidenceType::PolicyDocument, "T", "d");
        REQUIRE(r.isOk());
        CHECK(r.value().type == EvidenceType::PolicyDocument);
    }

    SUBCASE("ScanResult") {
        auto r = collector.addEvidence("C1", Framework::NIST, EvidenceType::ScanResult, "T", "d");
        REQUIRE(r.isOk());
        CHECK(r.value().type == EvidenceType::ScanResult);
    }
}
