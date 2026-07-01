#include <doctest/doctest.h>
#include <threat_intel/EnrichmentService.h>

#include <chrono>

using namespace ThreatOne::ThreatIntel;

TEST_CASE("EnrichmentService - Provider registration") {
    EnrichmentService service;

    SUBCASE("Initially no providers") {
        CHECK(service.providerCount() == 0);
    }

    SUBCASE("Register provider increases count") {
        auto provider = std::make_shared<ExternalEnrichmentProvider>("VirusTotal");
        service.registerProvider("vt", provider);
        CHECK(service.providerCount() == 1);
    }

    SUBCASE("Get provider names") {
        auto p1 = std::make_shared<ExternalEnrichmentProvider>("VT");
        auto p2 = std::make_shared<ExternalEnrichmentProvider>("AbuseIPDB");
        service.registerProvider("vt", p1);
        service.registerProvider("abuse", p2);

        auto names = service.getProviderNames();
        CHECK(names.size() == 2);
    }
}

TEST_CASE("EnrichmentService - Local enrichment") {
    IOCManager iocManager;
    ThreatCorrelationEngine correlationEngine;
    MitreAttackMatrix mitreMatrix;

    auto now = std::chrono::system_clock::now();

    // Add IOCs with shared source
    IOC ioc1;
    ioc1.type = IOCType::IP;
    ioc1.value = "10.0.0.1";
    ioc1.source = "APT_group";
    ioc1.confidence = 0.9;
    ioc1.firstSeen = now;
    ioc1.lastSeen = now;
    ioc1.active = true;
    auto result1 = iocManager.addIOC(ioc1);
    REQUIRE(result1.isOk());
    uint64_t id1 = result1.value();

    IOC ioc2;
    ioc2.type = IOCType::Domain;
    ioc2.value = "c2.evil.com";
    ioc2.source = "APT_group";
    ioc2.confidence = 0.85;
    ioc2.firstSeen = now;
    ioc2.lastSeen = now;
    ioc2.active = true;
    iocManager.addIOC(ioc2);

    LocalEnrichmentProvider localProvider(iocManager, correlationEngine, mitreMatrix);

    SUBCASE("Local enrichment returns context") {
        auto getResult = iocManager.getIOCById(id1);
        REQUIRE(getResult.isOk());
        auto enriched = localProvider.enrich(getResult.value());

        CHECK(enriched.originalIOC.value == "10.0.0.1");
        CHECK(!enriched.additionalContext.empty());
        CHECK(enriched.additionalContext["enrichment_provider"] == "local");
    }

    SUBCASE("Local enrichment finds related IOCs") {
        auto getResult = iocManager.getIOCById(id1);
        REQUIRE(getResult.isOk());
        auto enriched = localProvider.enrich(getResult.value());

        // Should find ioc2 as related (same source)
        CHECK(!enriched.relatedIOCs.empty());
    }

    SUBCASE("Local enrichment discovers TTPs for network IOC") {
        auto getResult = iocManager.getIOCById(id1);
        REQUIRE(getResult.isOk());
        auto enriched = localProvider.enrich(getResult.value());

        // IP type should trigger "network" search in MITRE, finding techniques
        CHECK(!enriched.ttps.empty());
    }
}

TEST_CASE("EnrichmentService - External enrichment stub") {
    ExternalEnrichmentProvider vtProvider("VirusTotal", "fake_api_key");

    SUBCASE("Provider name is correct") {
        CHECK(vtProvider.providerName() == "VirusTotal");
    }

    SUBCASE("Returns unavailable status") {
        IOC ioc;
        ioc.type = IOCType::IP;
        ioc.value = "10.0.0.1";
        ioc.source = "test";

        auto result = vtProvider.enrich(ioc);
        CHECK(result.originalIOC.value == "10.0.0.1");
        CHECK(result.additionalContext["status"] == "unavailable");
        CHECK(result.additionalContext["enrichment_provider"] == "VirusTotal");
    }
}

TEST_CASE("EnrichmentService - Batch enrichment") {
    EnrichmentService service;
    auto extProvider = std::make_shared<ExternalEnrichmentProvider>("TestProvider");
    service.registerProvider("test", extProvider);

    SUBCASE("Batch processes all IOCs") {
        std::vector<IOC> iocs;
        IOC ioc1;
        ioc1.type = IOCType::IP;
        ioc1.value = "10.0.0.1";
        ioc1.source = "s";
        iocs.push_back(ioc1);

        IOC ioc2;
        ioc2.type = IOCType::Domain;
        ioc2.value = "evil.com";
        ioc2.source = "s";
        iocs.push_back(ioc2);

        IOC ioc3;
        ioc3.type = IOCType::Hash_SHA256;
        ioc3.value = "abc123";
        ioc3.source = "s";
        iocs.push_back(ioc3);

        auto results = service.enrichBatch(iocs);
        CHECK(results.size() == 3);
        CHECK(results[0].originalIOC.value == "10.0.0.1");
        CHECK(results[1].originalIOC.value == "evil.com");
        CHECK(results[2].originalIOC.value == "abc123");
    }

    SUBCASE("Empty batch returns empty results") {
        std::vector<IOC> empty;
        auto results = service.enrichBatch(empty);
        CHECK(results.empty());
    }
}

TEST_CASE("EnrichmentService - Combined enrichment from multiple providers") {
    IOCManager iocManager;
    ThreatCorrelationEngine correlationEngine;
    MitreAttackMatrix mitreMatrix;

    auto now = std::chrono::system_clock::now();
    IOC ioc;
    ioc.type = IOCType::IP;
    ioc.value = "10.0.0.1";
    ioc.source = "test_source";
    ioc.confidence = 0.8;
    ioc.firstSeen = now;
    ioc.lastSeen = now;
    ioc.active = true;
    iocManager.addIOC(ioc);

    EnrichmentService service;
    auto localProvider = std::make_shared<LocalEnrichmentProvider>(
        iocManager, correlationEngine, mitreMatrix);
    auto extProvider = std::make_shared<ExternalEnrichmentProvider>("VT");

    service.registerProvider("local", localProvider);
    service.registerProvider("external", extProvider);

    SUBCASE("Combined result merges context from all providers") {
        auto result = service.enrich(ioc);
        // Should have context from both providers (prefixed)
        CHECK(result.additionalContext.count("local.enrichment_provider") > 0);
        CHECK(result.additionalContext.count("external.enrichment_provider") > 0);
    }
}
