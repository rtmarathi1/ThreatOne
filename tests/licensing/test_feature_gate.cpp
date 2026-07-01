#include <doctest/doctest.h>
#include <licensing/FeatureGate.h>

using namespace ThreatOne::Licensing;

TEST_CASE("FeatureGate - Default tier is Free") {
    FeatureGate gate;
    CHECK(gate.getCurrentTier() == LicenseType::Free);
}

TEST_CASE("FeatureGate - Register and check Free feature") {
    FeatureGate gate;
    gate.registerFeature("basic_scan", LicenseType::Free, "Basic scanning");
    CHECK(gate.isEnabled("basic_scan"));
}

TEST_CASE("FeatureGate - Pro feature disabled at Free tier") {
    FeatureGate gate;
    gate.registerFeature("advanced_ai", LicenseType::Professional, "AI detection");
    CHECK_FALSE(gate.isEnabled("advanced_ai"));
}

TEST_CASE("FeatureGate - Pro feature enabled at Pro tier") {
    FeatureGate gate;
    gate.registerFeature("advanced_ai", LicenseType::Professional, "AI detection");
    gate.setCurrentTier(LicenseType::Professional);
    CHECK(gate.isEnabled("advanced_ai"));
}

TEST_CASE("FeatureGate - Enterprise feature enabled at Enterprise tier") {
    FeatureGate gate;
    gate.registerFeature("fleet_mgmt", LicenseType::Enterprise, "Fleet management");
    gate.setCurrentTier(LicenseType::Enterprise);
    CHECK(gate.isEnabled("fleet_mgmt"));
}

TEST_CASE("FeatureGate - Higher tier enables lower tier features") {
    FeatureGate gate;
    gate.registerFeature("basic", LicenseType::Free, "Basic");
    gate.registerFeature("pro_feature", LicenseType::Professional, "Pro");
    gate.registerFeature("ent_feature", LicenseType::Enterprise, "Ent");
    gate.setCurrentTier(LicenseType::Enterprise);
    CHECK(gate.isEnabled("basic"));
    CHECK(gate.isEnabled("pro_feature"));
    CHECK(gate.isEnabled("ent_feature"));
}

TEST_CASE("FeatureGate - Downgrade disables features") {
    FeatureGate gate;
    gate.registerFeature("pro_feature", LicenseType::Professional, "Pro");
    gate.setCurrentTier(LicenseType::Professional);
    CHECK(gate.isEnabled("pro_feature"));
    gate.setCurrentTier(LicenseType::Free);
    CHECK_FALSE(gate.isEnabled("pro_feature"));
}

TEST_CASE("FeatureGate - Unknown feature returns false") {
    FeatureGate gate;
    CHECK_FALSE(gate.isEnabled("nonexistent_feature"));
}

TEST_CASE("FeatureGate - Get required tier for registered feature") {
    FeatureGate gate;
    gate.registerFeature("sso", LicenseType::Enterprise, "SSO integration");
    auto tier = gate.getRequiredTier("sso");
    REQUIRE(tier.has_value());
    CHECK(tier.value() == LicenseType::Enterprise);
}

TEST_CASE("FeatureGate - Get required tier for unknown feature returns nullopt") {
    FeatureGate gate;
    auto tier = gate.getRequiredTier("unknown");
    CHECK_FALSE(tier.has_value());
}

TEST_CASE("FeatureGate - Get all features") {
    FeatureGate gate;
    gate.registerFeature("feat1", LicenseType::Free, "F1");
    gate.registerFeature("feat2", LicenseType::Professional, "F2");
    auto all = gate.getAllFeatures();
    CHECK(all.size() == 2);
}

TEST_CASE("FeatureGate - Get enabled features at Free tier") {
    FeatureGate gate;
    gate.registerFeature("free_feat", LicenseType::Free, "Free");
    gate.registerFeature("pro_feat", LicenseType::Professional, "Pro");
    auto enabled = gate.getEnabledFeatures();
    CHECK(enabled.size() == 1);
    CHECK(enabled[0].name == "free_feat");
}

TEST_CASE("FeatureGate - Get disabled features") {
    FeatureGate gate;
    gate.registerFeature("free_feat", LicenseType::Free, "Free");
    gate.registerFeature("pro_feat", LicenseType::Professional, "Pro");
    auto disabled = gate.getDisabledFeatures();
    CHECK(disabled.size() == 1);
    CHECK(disabled[0].name == "pro_feat");
}

TEST_CASE("FeatureGate - Degradation info for disabled feature") {
    FeatureGate gate;
    gate.registerFeature("enterprise_only", LicenseType::Enterprise, "Enterprise feature");
    auto info = gate.getDegradationInfo("enterprise_only");
    REQUIRE(info.has_value());
    CHECK(info->featureName == "enterprise_only");
    CHECK(info->requiredTier == LicenseType::Enterprise);
    CHECK(info->currentTier == LicenseType::Free);
    CHECK_FALSE(info->message.empty());
}

TEST_CASE("FeatureGate - No degradation info for enabled feature") {
    FeatureGate gate;
    gate.registerFeature("basic", LicenseType::Free, "Basic");
    auto info = gate.getDegradationInfo("basic");
    CHECK_FALSE(info.has_value());
}

TEST_CASE("FeatureGate - Degradation callback is invoked") {
    FeatureGate gate;
    gate.registerFeature("premium", LicenseType::Professional, "Premium");

    bool callbackInvoked = false;
    gate.setDegradationCallback([&](const DegradationInfo& info) {
        callbackInvoked = true;
        CHECK(info.featureName == "premium");
    });

    auto degradation = gate.getDegradationInfo("premium");
    CHECK(callbackInvoked);
    CHECK(degradation.has_value());
}

TEST_CASE("FeatureGate - Track usage for enabled feature") {
    FeatureGate gate;
    gate.registerFeature("basic", LicenseType::Free, "Basic");
    CHECK(gate.trackUsage("basic"));
    CHECK(gate.trackUsage("basic"));
    CHECK(gate.getUsageCount("basic") == 2);
}

TEST_CASE("FeatureGate - Track usage fails for disabled feature") {
    FeatureGate gate;
    gate.registerFeature("pro_feat", LicenseType::Professional, "Pro");
    CHECK_FALSE(gate.trackUsage("pro_feat"));
    CHECK(gate.getUsageCount("pro_feat") == 0);
}

TEST_CASE("FeatureGate - Usage count for untracked feature is zero") {
    FeatureGate gate;
    CHECK(gate.getUsageCount("never_used") == 0);
}

TEST_CASE("FeatureGate - Unregister feature") {
    FeatureGate gate;
    gate.registerFeature("temp", LicenseType::Free, "Temporary");
    CHECK(gate.isEnabled("temp"));
    CHECK(gate.unregisterFeature("temp"));
    CHECK_FALSE(gate.isEnabled("temp"));
}

TEST_CASE("FeatureGate - Unregister nonexistent feature returns false") {
    FeatureGate gate;
    CHECK_FALSE(gate.unregisterFeature("ghost"));
}

TEST_CASE("FeatureGate - tierMeetsRequirement comparisons") {
    CHECK(FeatureGate::tierMeetsRequirement(LicenseType::Free, LicenseType::Free));
    CHECK_FALSE(FeatureGate::tierMeetsRequirement(LicenseType::Free, LicenseType::Professional));
    CHECK(FeatureGate::tierMeetsRequirement(LicenseType::Professional, LicenseType::Free));
    CHECK(FeatureGate::tierMeetsRequirement(LicenseType::Professional, LicenseType::Professional));
    CHECK_FALSE(FeatureGate::tierMeetsRequirement(LicenseType::Professional, LicenseType::Enterprise));
    CHECK(FeatureGate::tierMeetsRequirement(LicenseType::Enterprise, LicenseType::Professional));
    CHECK(FeatureGate::tierMeetsRequirement(LicenseType::Ultimate, LicenseType::Enterprise));
}

TEST_CASE("FeatureGate - Tier upgrade enables previously disabled features") {
    FeatureGate gate;
    gate.registerFeature("basic", LicenseType::Free, "Basic");
    gate.registerFeature("pro", LicenseType::Professional, "Pro");
    gate.registerFeature("ent", LicenseType::Enterprise, "Enterprise");
    gate.registerFeature("ult", LicenseType::Ultimate, "Ultimate");

    // At Free tier
    CHECK(gate.isEnabled("basic"));
    CHECK_FALSE(gate.isEnabled("pro"));
    CHECK_FALSE(gate.isEnabled("ent"));
    CHECK_FALSE(gate.isEnabled("ult"));

    // Upgrade to Ultimate
    gate.setCurrentTier(LicenseType::Ultimate);
    CHECK(gate.isEnabled("basic"));
    CHECK(gate.isEnabled("pro"));
    CHECK(gate.isEnabled("ent"));
    CHECK(gate.isEnabled("ult"));
}
