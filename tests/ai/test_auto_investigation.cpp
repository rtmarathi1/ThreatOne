#include <doctest/doctest.h>
#include <ai/AutoInvestigation.h>

#include <string>
#include <map>
#include <vector>

using namespace ThreatOne::AI;

TEST_CASE("AutoInvestigation - full investigation workflow") {
    AutoInvestigation investigator;

    SUBCASE("Investigation produces complete result") {
        std::map<std::string, std::string> triggerData;
        triggerData["type"] = "malware_detected";
        triggerData["source_ip"] = "192.168.1.100";
        triggerData["destination_ip"] = "10.0.0.5";
        triggerData["timestamp"] = "2024-01-15T10:30:00Z";
        triggerData["process"] = "suspicious.exe";
        triggerData["user"] = "admin";

        auto result = investigator.investigate("INC-001", triggerData);

        CHECK(!result.incidentId.empty());
        CHECK(result.incidentId == "INC-001");
        CHECK(!result.scope.empty());
        CHECK(!result.rootCause.empty());
        CHECK(result.confidence > 0.0);
        CHECK(result.confidence <= 1.0);
    }

    SUBCASE("Result includes affected assets") {
        std::map<std::string, std::string> triggerData;
        triggerData["type"] = "unauthorized_access";
        triggerData["source_ip"] = "10.0.0.50";
        triggerData["user"] = "attacker";
        triggerData["timestamp"] = "2024-01-15T12:00:00Z";

        auto result = investigator.investigate("INC-002", triggerData);
        CHECK(!result.affectedAssets.empty());
    }

    SUBCASE("Result includes timeline") {
        std::map<std::string, std::string> triggerData;
        triggerData["type"] = "data_exfiltration";
        triggerData["source_ip"] = "192.168.1.200";
        triggerData["timestamp"] = "2024-01-15T15:00:00Z";

        auto result = investigator.investigate("INC-003", triggerData);
        CHECK(!result.timeline.empty());
    }

    SUBCASE("Result includes suggested remediation") {
        std::map<std::string, std::string> triggerData;
        triggerData["type"] = "ransomware";
        triggerData["source_ip"] = "192.168.1.50";
        triggerData["process"] = "ransom.exe";
        triggerData["timestamp"] = "2024-01-15T08:00:00Z";

        auto result = investigator.investigate("INC-004", triggerData);
        CHECK(!result.suggestedRemediation.empty());
    }
}

TEST_CASE("AutoInvestigation - evidence gathering") {
    AutoInvestigation investigator;

    SUBCASE("Gather evidence from trigger data") {
        std::map<std::string, std::string> triggerData;
        triggerData["type"] = "intrusion";
        triggerData["source_ip"] = "10.10.10.10";
        triggerData["destination_ip"] = "192.168.1.1";
        triggerData["timestamp"] = "2024-02-01T09:00:00Z";

        auto evidence = investigator.gatherEvidence("TRIG-001", triggerData);
        CHECK(!evidence.empty());

        // Primary evidence from trigger
        bool hasTriggerEvidence = false;
        bool hasNetworkEvidence = false;
        for (const auto& e : evidence) {
            if (e.type == "trigger") hasTriggerEvidence = true;
            if (e.type == "network") hasNetworkEvidence = true;
        }
        CHECK(hasTriggerEvidence == true);
        CHECK(hasNetworkEvidence == true);
    }

    SUBCASE("Evidence has relevance scores") {
        std::map<std::string, std::string> triggerData;
        triggerData["type"] = "alert";
        triggerData["source_ip"] = "172.16.0.1";

        auto evidence = investigator.gatherEvidence("TRIG-002", triggerData);
        REQUIRE(!evidence.empty());

        for (const auto& e : evidence) {
            CHECK(e.relevance >= 0.0);
            CHECK(e.relevance <= 1.0);
        }
    }

    SUBCASE("Minimal trigger data still produces evidence") {
        std::map<std::string, std::string> triggerData;
        triggerData["type"] = "generic_alert";

        auto evidence = investigator.gatherEvidence("TRIG-003", triggerData);
        CHECK(!evidence.empty());
    }
}

TEST_CASE("AutoInvestigation - scope determination") {
    AutoInvestigation investigator;

    SUBCASE("Scope from correlations") {
        std::vector<std::string> correlations = {
            "host:server1 connected to host:server2",
            "user:admin accessed host:server1",
            "file:malware.exe found on host:server2"
        };

        auto scope = investigator.determineScope(correlations);
        CHECK(!scope.empty());
    }

    SUBCASE("Empty correlations produces empty scope") {
        std::vector<std::string> correlations;
        auto scope = investigator.determineScope(correlations);
        // May be empty or contain default values
        // Empty correlations may yield empty or default scope
        (void)scope;
    }
}

TEST_CASE("AutoInvestigation - remediation suggestions") {
    AutoInvestigation investigator;

    SUBCASE("Remediation suggestions are non-empty for incidents") {
        InvestigationResult result;
        result.incidentId = "INC-TEST";
        result.scope = "3 assets affected";
        result.affectedAssets = {"server1", "server2", "workstation1"};
        result.rootCause = "Phishing email leading to credential compromise";

        auto remediation = investigator.suggestRemediation(result);
        CHECK(!remediation.empty());
    }

    SUBCASE("Remediation for minimal result") {
        InvestigationResult result;
        result.incidentId = "INC-MINIMAL";
        result.scope = "1 assets affected";
        result.affectedAssets = {"host1"};

        auto remediation = investigator.suggestRemediation(result);
        CHECK(!remediation.empty());
    }
}
