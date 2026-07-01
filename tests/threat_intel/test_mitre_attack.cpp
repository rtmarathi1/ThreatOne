#include <doctest/doctest.h>
#include <threat_intel/MitreAttack.h>

using namespace ThreatOne::ThreatIntel;

TEST_CASE("MitreAttackMatrix - Technique lookup by ID") {
    MitreAttackMatrix matrix;

    SUBCASE("Known technique T1059 found") {
        auto result = matrix.getTechniqueById("T1059");
        REQUIRE(result.isOk());
        CHECK(result.value().id == "T1059");
        CHECK(!result.value().name.empty());
    }

    SUBCASE("Known technique T1053 found") {
        auto result = matrix.getTechniqueById("T1053");
        REQUIRE(result.isOk());
        CHECK(result.value().id == "T1053");
    }

    SUBCASE("Non-existent technique returns error") {
        auto result = matrix.getTechniqueById("T9999");
        CHECK(result.isErr());
    }

    SUBCASE("Pre-populated with many techniques") {
        CHECK(matrix.techniqueCount() >= 20);
    }
}

TEST_CASE("MitreAttackMatrix - Tactic operations") {
    MitreAttackMatrix matrix;

    SUBCASE("All tactics accessible") {
        auto tactics = matrix.getAllTactics();
        CHECK(tactics.size() >= 10);
    }

    SUBCASE("Tactic count is reasonable") {
        CHECK(matrix.tacticCount() >= 10);
    }

    SUBCASE("Techniques for a tactic") {
        // TA0001 = Initial Access
        auto techniques = matrix.getTechniquesByTactic("TA0001");
        CHECK(!techniques.empty());
        for (const auto& tech : techniques) {
            CHECK(!tech.id.empty());
            CHECK(!tech.name.empty());
        }
    }

    SUBCASE("Non-existent tactic returns empty") {
        auto techniques = matrix.getTechniquesByTactic("TA9999");
        CHECK(techniques.empty());
    }
}

TEST_CASE("MitreAttackMatrix - Search and detection mapping") {
    MitreAttackMatrix matrix;

    SUBCASE("Search by keyword finds matching techniques") {
        auto results = matrix.searchTechniques("script");
        CHECK(!results.empty());
        // T1059 is "Command and Scripting Interpreter"
        bool foundScripting = false;
        for (const auto& tech : results) {
            if (tech.id == "T1059") {
                foundScripting = true;
                break;
            }
        }
        CHECK(foundScripting);
    }

    SUBCASE("Search with no matches returns empty") {
        auto results = matrix.searchTechniques("zzzznonexistentzzz");
        CHECK(results.empty());
    }

    SUBCASE("Map detection info to techniques") {
        auto results = matrix.mapDetectionToTechnique("command line execution detected");
        // Should find T1059 "Command and Scripting Interpreter" since its detection is "command line"
        CHECK(!results.empty());
    }

    SUBCASE("Add custom technique") {
        Technique custom;
        custom.id = "T9001";
        custom.name = "Custom Technique";
        custom.description = "A test technique";
        custom.tactics = {"TA0001"};

        size_t before = matrix.techniqueCount();
        matrix.addTechnique(custom);
        CHECK(matrix.techniqueCount() == before + 1);

        auto result = matrix.getTechniqueById("T9001");
        REQUIRE(result.isOk());
        CHECK(result.value().name == "Custom Technique");
    }
}
