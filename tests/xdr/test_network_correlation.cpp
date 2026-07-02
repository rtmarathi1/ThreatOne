#include <doctest/doctest.h>
#include <xdr/NetworkCorrelation.h>
#include <string>
#include <vector>

using namespace ThreatOne::XDR;

TEST_CASE("NetworkCorrelation - Submit network event") {
    NetworkCorrelation nc;

    NetworkEvent event;
    event.sourceIP = "192.168.1.10";
    event.destIP = "10.0.0.1";
    event.destPort = 443;
    event.protocol = "TCP";
    event.endpointId = "EP-001";
    event.timestamp = "2024-01-15T10:00:00";

    std::string id = nc.submitNetworkEvent(event);
    CHECK_FALSE(id.empty());
    CHECK(nc.getEventCount() == 1);
}

TEST_CASE("NetworkCorrelation - Get events by endpoint") {
    NetworkCorrelation nc;

    NetworkEvent e1;
    e1.sourceIP = "192.168.1.10";
    e1.destIP = "8.8.8.8";
    e1.endpointId = "EP-001";
    nc.submitNetworkEvent(e1);

    NetworkEvent e2;
    e2.sourceIP = "192.168.1.10";
    e2.destIP = "1.1.1.1";
    e2.endpointId = "EP-001";
    nc.submitNetworkEvent(e2);

    NetworkEvent e3;
    e3.sourceIP = "192.168.1.20";
    e3.destIP = "8.8.8.8";
    e3.endpointId = "EP-002";
    nc.submitNetworkEvent(e3);

    auto ep1Events = nc.getNetworkEvents("EP-001");
    CHECK(ep1Events.size() == 2);

    auto allEvents = nc.getNetworkEvents("");
    CHECK(allEvents.size() == 3);
}

TEST_CASE("NetworkCorrelation - Detect lateral movement") {
    NetworkCorrelation nc;

    // Create connections from one internal IP to many internal IPs
    for (int i = 1; i <= 5; i++) {
        NetworkEvent event;
        event.sourceIP = "192.168.1.10";
        event.destIP = "192.168.1." + std::to_string(100 + i);
        event.destPort = 445;
        event.protocol = "TCP";
        event.endpointId = "EP-001";
        nc.submitNetworkEvent(event);
    }

    auto detections = nc.detectLateralMovement();
    REQUIRE_FALSE(detections.empty());
    CHECK(detections[0].sourceEndpoint == "192.168.1.10");
    CHECK(detections[0].targetEndpoints.size() >= 3);
    CHECK(detections[0].confidence > 0.0);
}

TEST_CASE("NetworkCorrelation - Detect C2 communication") {
    NetworkCorrelation nc;

    // Multiple connections from same endpoint to same external IP
    for (int i = 0; i < 5; i++) {
        NetworkEvent event;
        event.sourceIP = "192.168.1.10";
        event.destIP = "203.0.113.50";
        event.destPort = 8443;
        event.protocol = "TCP";
        event.endpointId = "EP-001";
        event.timestamp = "2024-01-15T10:0" + std::to_string(i) + ":00";
        nc.submitNetworkEvent(event);
    }

    auto detections = nc.detectC2Communication();
    REQUIRE_FALSE(detections.empty());
    CHECK(detections[0].endpointId == "EP-001");
    CHECK(detections[0].destIP == "203.0.113.50");
    CHECK(detections[0].confidence > 0.0);
}

TEST_CASE("NetworkCorrelation - Detect exfiltration") {
    NetworkCorrelation nc;

    // Large outbound transfer
    NetworkEvent event;
    event.sourceIP = "192.168.1.10";
    event.destIP = "203.0.113.99";
    event.destPort = 443;
    event.protocol = "TCP";
    event.endpointId = "EP-001";
    event.direction = "outbound";
    event.bytesTransferred = 200 * 1024 * 1024;  // 200 MB
    nc.submitNetworkEvent(event);

    auto detections = nc.detectExfiltration();
    REQUIRE_FALSE(detections.empty());
    CHECK(detections[0].endpointId == "EP-001");
    CHECK(detections[0].totalBytes > 100 * 1024 * 1024);
}

TEST_CASE("NetworkCorrelation - Suspicious DNS detection") {
    NetworkCorrelation nc;

    NetworkEvent normalDns;
    normalDns.sourceIP = "192.168.1.10";
    normalDns.destIP = "8.8.8.8";
    normalDns.protocol = "DNS";
    normalDns.dnsQuery = "google.com";
    normalDns.endpointId = "EP-001";
    nc.submitNetworkEvent(normalDns);

    NetworkEvent dgaDns;
    dgaDns.sourceIP = "192.168.1.10";
    dgaDns.destIP = "8.8.8.8";
    dgaDns.protocol = "DNS";
    dgaDns.dnsQuery = "xkrjlmnpqrst3847xyz.com";
    dgaDns.endpointId = "EP-001";
    nc.submitNetworkEvent(dgaDns);

    auto suspicious = nc.getSuspiciousDNSQueries();
    CHECK_FALSE(suspicious.empty());
}

TEST_CASE("NetworkCorrelation - Correlate network activity") {
    NetworkCorrelation nc;

    NetworkEvent e1;
    e1.sourceIP = "192.168.1.10";
    e1.destIP = "203.0.113.50";
    e1.endpointId = "EP-001";
    std::string id1 = nc.submitNetworkEvent(e1);

    NetworkEvent e2;
    e2.sourceIP = "192.168.1.20";
    e2.destIP = "203.0.113.50";
    e2.endpointId = "EP-002";
    std::string id2 = nc.submitNetworkEvent(e2);

    auto correlations = nc.correlateNetworkActivity({id1, id2});
    REQUIRE_FALSE(correlations.empty());
    CHECK(correlations[0].eventIds.size() == 2);
}

TEST_CASE("NetworkCorrelation - Unique endpoints count") {
    NetworkCorrelation nc;

    NetworkEvent e1;
    e1.endpointId = "EP-001";
    e1.sourceIP = "192.168.1.10";
    e1.destIP = "8.8.8.8";
    nc.submitNetworkEvent(e1);

    NetworkEvent e2;
    e2.endpointId = "EP-002";
    e2.sourceIP = "192.168.1.20";
    e2.destIP = "8.8.8.8";
    nc.submitNetworkEvent(e2);

    CHECK(nc.getUniqueEndpoints() == 2);
}
