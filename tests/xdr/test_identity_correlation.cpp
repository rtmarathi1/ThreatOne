#include <doctest/doctest.h>
#include <xdr/IdentityCorrelation.h>
#include <string>
#include <vector>

using namespace ThreatOne::XDR;

TEST_CASE("IdentityCorrelation - Submit identity event") {
    IdentityCorrelation ic;

    IdentityEvent event;
    event.userId = "user1";
    event.eventType = "login";
    event.sourceIP = "192.168.1.10";
    event.system = "active_directory";
    event.timestamp = "2024-01-15T10:00:00";

    std::string id = ic.submitIdentityEvent(event);
    CHECK_FALSE(id.empty());
    CHECK(ic.getEventCount() == 1);
}

TEST_CASE("IdentityCorrelation - Get events by user") {
    IdentityCorrelation ic;

    IdentityEvent e1;
    e1.userId = "user1";
    e1.eventType = "login";
    ic.submitIdentityEvent(e1);

    IdentityEvent e2;
    e2.userId = "user1";
    e2.eventType = "logout";
    ic.submitIdentityEvent(e2);

    IdentityEvent e3;
    e3.userId = "user2";
    e3.eventType = "login";
    ic.submitIdentityEvent(e3);

    auto user1Events = ic.getIdentityEvents("user1");
    CHECK(user1Events.size() == 2);

    auto allEvents = ic.getIdentityEvents("");
    CHECK(allEvents.size() == 3);
}

TEST_CASE("IdentityCorrelation - Detect brute force") {
    IdentityCorrelation ic;

    for (int i = 0; i < 5; i++) {
        IdentityEvent event;
        event.userId = "target_user";
        event.eventType = "failed_login";
        event.sourceIP = "10.0.0." + std::to_string(i);
        event.timestamp = "2024-01-15T10:0" + std::to_string(i) + ":00";
        ic.submitIdentityEvent(event);
    }

    CHECK(ic.isBruteForceDetected("target_user"));
    CHECK_FALSE(ic.isBruteForceDetected("other_user"));
}

TEST_CASE("IdentityCorrelation - Detect impossible travel") {
    IdentityCorrelation ic;

    IdentityEvent e1;
    e1.userId = "user1";
    e1.eventType = "login";
    e1.geoLocation = "New York, US";
    e1.timestamp = "2024-01-15T10:00:00";
    ic.submitIdentityEvent(e1);

    IdentityEvent e2;
    e2.userId = "user1";
    e2.eventType = "login";
    e2.geoLocation = "Tokyo, JP";
    e2.timestamp = "2024-01-15T10:30:00";
    ic.submitIdentityEvent(e2);

    CHECK(ic.isImpossibleTravel("user1"));
    CHECK_FALSE(ic.isImpossibleTravel("user2"));
}

TEST_CASE("IdentityCorrelation - Detect identity threats") {
    IdentityCorrelation ic;

    // Add brute force events
    for (int i = 0; i < 4; i++) {
        IdentityEvent event;
        event.userId = "victim";
        event.eventType = "failed_login";
        ic.submitIdentityEvent(event);
    }

    // Add privilege escalation
    IdentityEvent privEsc;
    privEsc.userId = "attacker";
    privEsc.eventType = "privilege_escalation";
    ic.submitIdentityEvent(privEsc);

    auto threats = ic.detectIdentityThreats();
    CHECK(threats.size() >= 2);

    bool foundBruteForce = false;
    bool foundPrivAbuse = false;
    for (const auto& t : threats) {
        if (t.threatType == "brute_force") foundBruteForce = true;
        if (t.threatType == "privilege_abuse") foundPrivAbuse = true;
    }
    CHECK(foundBruteForce);
    CHECK(foundPrivAbuse);
}

TEST_CASE("IdentityCorrelation - Detect access anomalies") {
    IdentityCorrelation ic;

    // User accessing many different systems
    for (int i = 0; i < 5; i++) {
        IdentityEvent event;
        event.userId = "suspicious_user";
        event.eventType = "login";
        event.system = "system_" + std::to_string(i);
        ic.submitIdentityEvent(event);
    }

    auto anomalies = ic.detectAccessAnomalies();
    REQUIRE_FALSE(anomalies.empty());
    CHECK(anomalies[0].anomalyType == "excessive_access");
    CHECK(anomalies[0].riskScore > 0.0);
}

TEST_CASE("IdentityCorrelation - Failed login count") {
    IdentityCorrelation ic;

    IdentityEvent e1;
    e1.userId = "user1";
    e1.eventType = "failed_login";
    ic.submitIdentityEvent(e1);

    IdentityEvent e2;
    e2.userId = "user1";
    e2.eventType = "login";
    ic.submitIdentityEvent(e2);

    IdentityEvent e3;
    e3.userId = "user1";
    e3.eventType = "failed_login";
    ic.submitIdentityEvent(e3);

    CHECK(ic.getFailedLoginCount("user1") == 2);
    CHECK(ic.getFailedLoginCount("user2") == 0);
}

TEST_CASE("IdentityCorrelation - Get active users") {
    IdentityCorrelation ic;

    IdentityEvent e1;
    e1.userId = "user1";
    e1.eventType = "login";
    ic.submitIdentityEvent(e1);

    IdentityEvent e2;
    e2.userId = "user2";
    e2.eventType = "login";
    ic.submitIdentityEvent(e2);

    auto users = ic.getActiveUsers();
    CHECK(users.size() == 2);
}
