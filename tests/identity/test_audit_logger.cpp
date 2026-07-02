#include <doctest/doctest.h>
#include <identity/AuditLogger.h>
#include <chrono>
#include <string>

using namespace ThreatOne::Identity;

TEST_CASE("AuditLogger - Log single event") {
    AuditLogger logger;
    std::string id = logger.logEvent("user-001", "login", "auth-service",
                                      AuditOutcome::Success, "192.168.1.1", "Login successful");
    CHECK_FALSE(id.empty());
    CHECK(logger.getEntryCount() == 1);
}

TEST_CASE("AuditLogger - Log multiple events") {
    AuditLogger logger;
    logger.logEvent("user-001", "login", "auth", AuditOutcome::Success);
    logger.logEvent("user-001", "read", "scanner", AuditOutcome::Success);
    logger.logEvent("user-002", "write", "config", AuditOutcome::Denied);
    CHECK(logger.getEntryCount() == 3);
}

TEST_CASE("AuditLogger - Entry has correct fields") {
    AuditLogger logger;
    std::string id = logger.logEvent("user-001", "login", "auth",
                                      AuditOutcome::Success, "10.0.0.1", "test details");
    auto entry = logger.getEntry(id);
    CHECK(entry.id == id);
    CHECK(entry.userId == "user-001");
    CHECK(entry.action == "login");
    CHECK(entry.resource == "auth");
    CHECK(entry.outcome == AuditOutcome::Success);
    CHECK(entry.sourceIP == "10.0.0.1");
    CHECK(entry.details == "test details");
    CHECK_FALSE(entry.hash.empty());
}

TEST_CASE("AuditLogger - First entry has empty previousHash") {
    AuditLogger logger;
    std::string id = logger.logEvent("user-001", "login", "auth", AuditOutcome::Success);
    auto entry = logger.getEntry(id);
    CHECK(entry.previousHash.empty());
}

TEST_CASE("AuditLogger - Second entry references first entry hash") {
    AuditLogger logger;
    std::string id1 = logger.logEvent("user-001", "login", "auth", AuditOutcome::Success);
    std::string id2 = logger.logEvent("user-001", "read", "scanner", AuditOutcome::Success);

    auto entry1 = logger.getEntry(id1);
    auto entry2 = logger.getEntry(id2);
    CHECK(entry2.previousHash == entry1.hash);
}

TEST_CASE("AuditLogger - Chain integrity verifies correctly") {
    AuditLogger logger;
    for (int i = 0; i < 10; ++i) {
        logger.logEvent("user-001", "action-" + std::to_string(i), "resource", AuditOutcome::Success);
    }
    CHECK(logger.verifyChainIntegrity());
}

TEST_CASE("AuditLogger - Each entry has unique hash") {
    AuditLogger logger;
    logger.logEvent("user-001", "action1", "res", AuditOutcome::Success);
    logger.logEvent("user-001", "action2", "res", AuditOutcome::Success);
    logger.logEvent("user-001", "action3", "res", AuditOutcome::Success);

    auto entries = logger.getEntries(10);
    CHECK(entries[0].hash != entries[1].hash);
    CHECK(entries[1].hash != entries[2].hash);
    CHECK(entries[0].hash != entries[2].hash);
}

TEST_CASE("AuditLogger - Verify individual entry") {
    AuditLogger logger;
    std::string id1 = logger.logEvent("user-001", "login", "auth", AuditOutcome::Success);
    std::string id2 = logger.logEvent("user-001", "read", "scanner", AuditOutcome::Success);

    CHECK(logger.verifyEntry(id1));
    CHECK(logger.verifyEntry(id2));
    CHECK(logger.verifyChainIntegrity());
}

TEST_CASE("AuditLogger - Search by userId") {
    AuditLogger logger;
    logger.logEvent("user-001", "login", "auth", AuditOutcome::Success);
    logger.logEvent("user-001", "read", "scanner", AuditOutcome::Success);
    logger.logEvent("user-002", "login", "auth", AuditOutcome::Failure);
    logger.logEvent("user-002", "write", "config", AuditOutcome::Denied);

    AuditSearchCriteria criteria;
    criteria.userId = "user-001";
    auto results = logger.search(criteria);
    CHECK(results.size() == 2);
}

TEST_CASE("AuditLogger - Search by action") {
    AuditLogger logger;
    logger.logEvent("user-001", "login", "auth", AuditOutcome::Success);
    logger.logEvent("user-001", "read", "scanner", AuditOutcome::Success);
    logger.logEvent("user-002", "login", "auth", AuditOutcome::Failure);

    AuditSearchCriteria criteria;
    criteria.action = "login";
    auto results = logger.search(criteria);
    CHECK(results.size() == 2);
}

TEST_CASE("AuditLogger - Search by resource") {
    AuditLogger logger;
    logger.logEvent("user-001", "login", "auth", AuditOutcome::Success);
    logger.logEvent("user-002", "login", "auth", AuditOutcome::Failure);
    logger.logEvent("user-001", "read", "scanner", AuditOutcome::Success);

    AuditSearchCriteria criteria;
    criteria.resource = "auth";
    auto results = logger.search(criteria);
    CHECK(results.size() == 2);
}

TEST_CASE("AuditLogger - Search by outcome") {
    AuditLogger logger;
    logger.logEvent("user-001", "login", "auth", AuditOutcome::Success);
    logger.logEvent("user-002", "write", "config", AuditOutcome::Denied);

    AuditSearchCriteria criteria;
    criteria.filterByOutcome = true;
    criteria.outcome = AuditOutcome::Denied;
    auto results = logger.search(criteria);
    CHECK(results.size() == 1);
    CHECK(results[0].userId == "user-002");
}

TEST_CASE("AuditLogger - Combined search criteria") {
    AuditLogger logger;
    logger.logEvent("user-001", "login", "auth", AuditOutcome::Success);
    logger.logEvent("user-002", "login", "auth", AuditOutcome::Failure);
    logger.logEvent("user-002", "write", "config", AuditOutcome::Denied);

    AuditSearchCriteria criteria;
    criteria.userId = "user-002";
    criteria.action = "login";
    auto results = logger.search(criteria);
    CHECK(results.size() == 1);
    CHECK(results[0].outcome == AuditOutcome::Failure);
}

TEST_CASE("AuditLogger - Max results limit") {
    AuditLogger logger;
    for (int i = 0; i < 10; ++i) {
        logger.logEvent("user", "action", "res", AuditOutcome::Success);
    }

    AuditSearchCriteria criteria;
    criteria.maxResults = 2;
    auto results = logger.search(criteria);
    CHECK(results.size() == 2);
}

TEST_CASE("AuditLogger - Get entries with offset") {
    AuditLogger logger;
    logger.logEvent("user-001", "login", "auth", AuditOutcome::Success);
    logger.logEvent("user-001", "read", "scanner", AuditOutcome::Success);
    logger.logEvent("user-002", "login", "auth", AuditOutcome::Failure);
    logger.logEvent("user-002", "write", "config", AuditOutcome::Denied);

    auto entries = logger.getEntries(2, 2);
    CHECK(entries.size() == 2);
    CHECK(entries[0].userId == "user-002");
}

TEST_CASE("AuditLogger - Set and get retention policy") {
    AuditLogger logger;
    RetentionPolicy policy;
    policy.maxEntries = 5;
    policy.enabled = true;
    logger.setRetentionPolicy(policy);

    auto retrieved = logger.getRetentionPolicy();
    CHECK(retrieved.maxEntries == 5);
    CHECK(retrieved.enabled);
}

TEST_CASE("AuditLogger - Enforce max entries") {
    AuditLogger logger;
    RetentionPolicy policy;
    policy.maxEntries = 3;
    policy.maxAge = std::chrono::seconds(86400);
    policy.enabled = true;
    logger.setRetentionPolicy(policy);

    // Log more than max entries
    for (int i = 0; i < 5; ++i) {
        logger.logEvent("user", "action", "res", AuditOutcome::Success);
    }

    // After enforcement (triggered automatically), should be at max
    CHECK(logger.getEntryCount() <= 3);
}
