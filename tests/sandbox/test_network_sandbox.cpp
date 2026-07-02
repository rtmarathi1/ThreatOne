#include <doctest/doctest.h>
#include <sandbox/SandboxEngine.h>

using namespace ThreatOne::Sandbox;

TEST_CASE("NetworkSandbox - Record DNS query") {
    SandboxEngine engine;
    auto& ns = engine.getNetworkSandbox();

    auto id = ns.recordDNSQuery("SAMPLE-1", "evil.com", "A");
    CHECK_FALSE(id.empty());
    CHECK(id.find("DNS-") == 0);

    auto queries = ns.getDNSQueries("SAMPLE-1");
    REQUIRE(queries.size() == 1);
    CHECK(queries[0].domain == "evil.com");
    CHECK(queries[0].queryType == "A");
}

TEST_CASE("NetworkSandbox - DNS response override") {
    SandboxEngine engine;
    auto& ns = engine.getNetworkSandbox();

    ns.setDNSResponse("malware.com", "192.168.1.100");
    CHECK(ns.resolveDNS("malware.com") == "192.168.1.100");

    // Default response for unknown domains
    CHECK(ns.resolveDNS("unknown.com") == "10.0.0.1");
}

TEST_CASE("NetworkSandbox - Record HTTP request") {
    SandboxEngine engine;
    auto& ns = engine.getNetworkSandbox();

    auto id = ns.recordHTTPRequest("SAMPLE-1", "GET", "http://evil.com/payload");
    CHECK_FALSE(id.empty());

    auto requests = ns.getHTTPRequests("SAMPLE-1");
    REQUIRE(requests.size() == 1);
    CHECK(requests[0].method == "GET");
    CHECK(requests[0].url == "http://evil.com/payload");
    CHECK(requests[0].host == "evil.com");
}

TEST_CASE("NetworkSandbox - Record C2 communication") {
    SandboxEngine engine;
    auto& ns = engine.getNetworkSandbox();

    auto id = ns.recordC2Communication("SAMPLE-1", "10.0.0.50", 4444, "TCP");
    CHECK_FALSE(id.empty());

    auto comms = ns.getC2Communications("SAMPLE-1");
    REQUIRE(comms.size() == 1);
    CHECK(comms[0].serverAddress == "10.0.0.50");
    CHECK(comms[0].port == 4444);
    CHECK(comms[0].protocol == "TCP");
}

TEST_CASE("NetworkSandbox - C2 pattern detection") {
    SandboxEngine engine;
    auto& ns = engine.getNetworkSandbox();

    CHECK_FALSE(ns.detectC2Pattern("SAMPLE-1"));

    ns.recordC2Communication("SAMPLE-1", "10.0.0.50", 4444, "TCP");
    CHECK(ns.detectC2Pattern("SAMPLE-1"));
}

TEST_CASE("NetworkSandbox - Network activities conversion") {
    SandboxEngine engine;
    auto& ns = engine.getNetworkSandbox();

    ns.recordDNSQuery("SAMPLE-1", "evil.com", "A");
    ns.recordHTTPRequest("SAMPLE-1", "POST", "http://evil.com/data");
    ns.recordC2Communication("SAMPLE-1", "10.0.0.50", 4444, "TCP");

    auto activities = ns.getNetworkActivities("SAMPLE-1");
    CHECK(activities.size() == 3);
}

TEST_CASE("NetworkSandbox - Statistics") {
    SandboxEngine engine;
    auto& ns = engine.getNetworkSandbox();

    ns.recordDNSQuery("S1", "a.com", "A");
    ns.recordDNSQuery("S2", "b.com", "A");
    ns.recordHTTPRequest("S1", "GET", "http://a.com");
    ns.recordC2Communication("S1", "1.2.3.4", 80, "TCP");

    CHECK(ns.getTotalDNSQueries() == 2);
    CHECK(ns.getTotalHTTPRequests() == 1);
    CHECK(ns.getTotalC2Detected() == 1);
}
