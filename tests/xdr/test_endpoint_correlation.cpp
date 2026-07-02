#include <doctest/doctest.h>
#include <xdr/EndpointCorrelation.h>
#include <string>
#include <vector>

using namespace ThreatOne::XDR;

TEST_CASE("EndpointCorrelation - Submit event returns ID") {
    EndpointCorrelation ec;

    EndpointEvent event;
    event.endpointId = "EP-001";
    event.eventType = "process_creation";
    event.timestamp = "2024-01-15T10:00:00";
    event.severity = "medium";

    std::string id = ec.submitEvent(event);
    CHECK_FALSE(id.empty());
    CHECK(ec.getEventCount() == 1);
}

TEST_CASE("EndpointCorrelation - Submit multiple events with unique IDs") {
    EndpointCorrelation ec;

    EndpointEvent e1;
    e1.endpointId = "EP-001";
    e1.eventType = "file_write";
    e1.timestamp = "2024-01-15T10:00:00";
    e1.severity = "low";

    EndpointEvent e2;
    e2.endpointId = "EP-001";
    e2.eventType = "network_connection";
    e2.timestamp = "2024-01-15T10:01:00";
    e2.severity = "medium";

    std::string id1 = ec.submitEvent(e1);
    std::string id2 = ec.submitEvent(e2);
    CHECK(id1 != id2);
    CHECK(ec.getEventCount() == 2);
}

TEST_CASE("EndpointCorrelation - Correlate events on same endpoint") {
    EndpointCorrelation ec;

    EndpointEvent e1;
    e1.endpointId = "EP-001";
    e1.eventType = "process_creation";
    e1.timestamp = "2024-01-15T10:00:00";
    e1.severity = "low";

    EndpointEvent e2;
    e2.endpointId = "EP-001";
    e2.eventType = "file_modification";
    e2.timestamp = "2024-01-15T10:02:00";
    e2.severity = "high";

    std::string id1 = ec.submitEvent(e1);
    std::string id2 = ec.submitEvent(e2);

    auto correlations = ec.correlateByEndpoint({id1, id2});
    REQUIRE(correlations.size() == 1);
    CHECK(correlations[0].eventIds.size() == 2);
    CHECK(correlations[0].severity == "high");
}

TEST_CASE("EndpointCorrelation - No correlation for different endpoints") {
    EndpointCorrelation ec;

    EndpointEvent e1;
    e1.endpointId = "EP-001";
    e1.eventType = "process";
    e1.timestamp = "2024-01-15T10:00:00";
    e1.severity = "low";

    EndpointEvent e2;
    e2.endpointId = "EP-002";
    e2.eventType = "network";
    e2.timestamp = "2024-01-15T10:00:00";
    e2.severity = "low";

    std::string id1 = ec.submitEvent(e1);
    std::string id2 = ec.submitEvent(e2);

    auto correlations = ec.correlateByEndpoint({id1, id2});
    CHECK(correlations.empty());
}

TEST_CASE("EndpointCorrelation - Escalating severity detection") {
    EndpointCorrelation ec;

    EndpointEvent e1;
    e1.endpointId = "EP-001";
    e1.eventType = "recon";
    e1.timestamp = "2024-01-15T10:00:00";
    e1.severity = "low";

    EndpointEvent e2;
    e2.endpointId = "EP-001";
    e2.eventType = "exploit";
    e2.timestamp = "2024-01-15T10:01:00";
    e2.severity = "medium";

    EndpointEvent e3;
    e3.endpointId = "EP-001";
    e3.eventType = "exfil";
    e3.timestamp = "2024-01-15T10:02:00";
    e3.severity = "critical";

    std::string id1 = ec.submitEvent(e1);
    std::string id2 = ec.submitEvent(e2);
    std::string id3 = ec.submitEvent(e3);

    auto correlations = ec.correlateByEndpoint({id1, id2, id3});
    REQUIRE_FALSE(correlations.empty());
    CHECK(correlations[0].description.find("Multi-stage") != std::string::npos);
    CHECK(correlations[0].confidence > 0.5);
}

TEST_CASE("EndpointCorrelation - Process tree") {
    EndpointCorrelation ec;

    ProcessNode root;
    root.processId = "P-1";
    root.processName = "explorer.exe";
    root.endpointId = "EP-001";

    ProcessNode child;
    child.processId = "P-2";
    child.parentProcessId = "P-1";
    child.processName = "cmd.exe";
    child.endpointId = "EP-001";

    ec.addProcessNode(root);
    ec.addProcessNode(child);

    auto tree = ec.getProcessTree("P-1");
    CHECK(tree.size() == 2);
}

TEST_CASE("EndpointCorrelation - Suspicious process detection") {
    EndpointCorrelation ec;

    ProcessNode node;
    node.processId = "P-1";
    node.processName = "powershell.exe";
    node.endpointId = "EP-001";
    ec.addProcessNode(node);

    CHECK(ec.isProcessSuspicious("P-1"));
    CHECK_FALSE(ec.isProcessSuspicious("P-999"));
}

TEST_CASE("EndpointCorrelation - Get events by endpoint") {
    EndpointCorrelation ec;

    EndpointEvent e1;
    e1.endpointId = "EP-001";
    e1.eventType = "process";
    e1.severity = "low";
    ec.submitEvent(e1);

    EndpointEvent e2;
    e2.endpointId = "EP-001";
    e2.eventType = "file";
    e2.severity = "low";
    ec.submitEvent(e2);

    EndpointEvent e3;
    e3.endpointId = "EP-002";
    e3.eventType = "network";
    e3.severity = "low";
    ec.submitEvent(e3);

    auto ep1Events = ec.getEventsByEndpoint("EP-001");
    CHECK(ep1Events.size() == 2);

    auto ep2Events = ec.getEventsByEndpoint("EP-002");
    CHECK(ep2Events.size() == 1);
}

TEST_CASE("EndpointCorrelation - Attack chain detection") {
    EndpointCorrelation ec;

    EndpointEvent e1;
    e1.endpointId = "EP-001";
    e1.eventType = "recon_scan";
    e1.timestamp = "2024-01-15T10:00:00";
    e1.severity = "low";
    ec.submitEvent(e1);

    EndpointEvent e2;
    e2.endpointId = "EP-001";
    e2.eventType = "exploitation_attempt";
    e2.timestamp = "2024-01-15T10:05:00";
    e2.severity = "high";
    ec.submitEvent(e2);

    auto chains = ec.detectAttackChains("EP-001");
    REQUIRE_FALSE(chains.empty());
    CHECK(chains[0].endpointId == "EP-001");
    CHECK_FALSE(chains[0].tactics.empty());
}
