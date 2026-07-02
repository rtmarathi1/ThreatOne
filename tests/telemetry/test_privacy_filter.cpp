#include <doctest/doctest.h>
#include <telemetry/TelemetryManager.h>

using namespace ThreatOne::Telemetry;

TEST_CASE("PrivacyFilter - Default rules loaded") {
    TelemetryManager mgr;
    auto& pf = mgr.getPrivacyFilter();

    auto rules = pf.getFilterRules();
    CHECK(rules.size() >= 3);
}

TEST_CASE("PrivacyFilter - Filter email") {
    TelemetryManager mgr;
    auto& pf = mgr.getPrivacyFilter();

    auto result = pf.filterValue("user@example.com");
    CHECK(result.modified == true);
    CHECK(result.filteredValue == "[EMAIL_REDACTED]");
}

TEST_CASE("PrivacyFilter - No filter on clean value") {
    TelemetryManager mgr;
    auto& pf = mgr.getPrivacyFilter();

    auto result = pf.filterValue("just a normal string");
    CHECK(result.modified == false);
    CHECK(result.filteredValue == "just a normal string");
}

TEST_CASE("PrivacyFilter - Filter event properties") {
    TelemetryManager mgr;
    auto& pf = mgr.getPrivacyFilter();

    pf.addBlockedField("password");

    TelemetryEvent event;
    event.name = "login";
    event.category = "auth";
    event.properties["username"] = "john";
    event.properties["password"] = "secret123";

    auto filtered = pf.filterEvent(event);
    CHECK(filtered.properties["password"] == "[BLOCKED]");
}

TEST_CASE("PrivacyFilter - Add custom rule") {
    TelemetryManager mgr;
    auto& pf = mgr.getPrivacyFilter();

    FilterRule rule;
    rule.name = "Credit Card";
    rule.type = PIIType::CreditCard;
    rule.pattern = "4111";
    rule.replacement = "[CC_REDACTED]";

    auto id = pf.addFilterRule(rule);
    CHECK_FALSE(id.empty());

    auto result = pf.filterValue("card: 4111-1111-1111-1111");
    CHECK(result.modified == true);
    CHECK(result.filteredValue == "[CC_REDACTED]");
}

TEST_CASE("PrivacyFilter - Field allowlist") {
    TelemetryManager mgr;
    auto& pf = mgr.getPrivacyFilter();

    pf.addAllowedField("safe_field");
    CHECK(pf.isFieldAllowed("safe_field"));
    CHECK_FALSE(pf.isFieldAllowed("other_field"));

    pf.removeAllowedField("safe_field");
}

TEST_CASE("PrivacyFilter - Data retention") {
    TelemetryManager mgr;
    auto& pf = mgr.getPrivacyFilter();

    CHECK(pf.getDataRetentionDays() == 90);
    CHECK(pf.setDataRetentionDays(30));
    CHECK(pf.getDataRetentionDays() == 30);
    CHECK_FALSE(pf.setDataRetentionDays(0));
}

TEST_CASE("PrivacyFilter - Statistics") {
    TelemetryManager mgr;
    auto& pf = mgr.getPrivacyFilter();

    pf.filterValue("normal");
    pf.filterValue("user@test.com");

    auto stats = pf.getStats();
    CHECK(stats.totalProcessed == 2);
    CHECK(stats.totalFiltered >= 1);

    pf.resetStats();
    stats = pf.getStats();
    CHECK(stats.totalProcessed == 0);
}
