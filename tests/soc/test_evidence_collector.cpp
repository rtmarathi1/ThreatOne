#include <doctest/doctest.h>
#include <soc/EvidenceCollector.h>
#include <string>

using namespace ThreatOne::SOC;

TEST_CASE("EvidenceCollector - Add evidence") {
    EvidenceCollector collector;

    EvidenceItem ev;
    ev.type = "log";
    ev.description = "Firewall log entry";
    ev.data = "SRC=192.168.1.1";
    ev.addedBy = "analyst-01";

    std::string id = collector.addEvidence("CASE-1", ev);
    CHECK_FALSE(id.empty());
    CHECK(id.find("EV-") == 0);
}

TEST_CASE("EvidenceCollector - Get evidence for case") {
    EvidenceCollector collector;

    EvidenceItem ev1;
    ev1.type = "log";
    ev1.addedBy = "analyst-01";
    collector.addEvidence("CASE-1", ev1);

    EvidenceItem ev2;
    ev2.type = "pcap";
    ev2.addedBy = "analyst-02";
    collector.addEvidence("CASE-1", ev2);

    auto evidence = collector.getEvidence("CASE-1");
    CHECK(evidence.size() == 2);
    CHECK(evidence[0].caseId == "CASE-1");
}

TEST_CASE("EvidenceCollector - Get evidence for empty case") {
    EvidenceCollector collector;
    auto evidence = collector.getEvidence("nonexistent");
    CHECK(evidence.empty());
}

TEST_CASE("EvidenceCollector - Get evidence by ID") {
    EvidenceCollector collector;

    EvidenceItem ev;
    ev.type = "memory_dump";
    ev.addedBy = "analyst-01";
    std::string id = collector.addEvidence("CASE-1", ev);

    auto retrieved = collector.getEvidenceById(id);
    CHECK(retrieved.id == id);
    CHECK(retrieved.type == "memory_dump");
}

TEST_CASE("EvidenceCollector - Remove evidence") {
    EvidenceCollector collector;

    EvidenceItem ev;
    ev.type = "log";
    ev.addedBy = "analyst-01";
    std::string id = collector.addEvidence("CASE-1", ev);

    CHECK(collector.removeEvidence(id));
    CHECK_FALSE(collector.evidenceExists(id));
    CHECK_FALSE(collector.removeEvidence("nonexistent"));
}

TEST_CASE("EvidenceCollector - Chain of custody") {
    EvidenceCollector collector;

    EvidenceItem ev;
    ev.type = "disk_image";
    ev.addedBy = "analyst-01";
    std::string id = collector.addEvidence("CASE-1", ev);

    // Initial custody entry is created automatically
    auto chain = collector.getCustodyChain(id);
    CHECK(chain.size() == 1);
    CHECK(chain[0].action == "collected");

    ChainOfCustodyEntry entry;
    entry.action = "transferred";
    entry.performer = "analyst-02";
    entry.notes = "Transferred for analysis";
    CHECK(collector.addCustodyEntry(id, entry));

    chain = collector.getCustodyChain(id);
    CHECK(chain.size() == 2);

    CHECK_FALSE(collector.addCustodyEntry("nonexistent", entry));
}

TEST_CASE("EvidenceCollector - Evidence count") {
    EvidenceCollector collector;
    CHECK(collector.getEvidenceCount() == 0);

    EvidenceItem ev;
    ev.type = "log";
    ev.addedBy = "analyst-01";
    collector.addEvidence("CASE-1", ev);
    collector.addEvidence("CASE-2", ev);

    CHECK(collector.getEvidenceCount() == 2);
    CHECK(collector.getEvidenceCountForCase("CASE-1") == 1);
}

TEST_CASE("EvidenceCollector - Get evidence by type") {
    EvidenceCollector collector;

    EvidenceItem ev1;
    ev1.type = "log";
    ev1.addedBy = "analyst-01";
    collector.addEvidence("CASE-1", ev1);

    EvidenceItem ev2;
    ev2.type = "pcap";
    ev2.addedBy = "analyst-02";
    collector.addEvidence("CASE-1", ev2);

    EvidenceItem ev3;
    ev3.type = "log";
    ev3.addedBy = "analyst-03";
    collector.addEvidence("CASE-2", ev3);

    auto logs = collector.getEvidenceByType("log");
    CHECK(logs.size() == 2);

    auto pcaps = collector.getEvidenceByType("pcap");
    CHECK(pcaps.size() == 1);
}
