#include <doctest/doctest.h>
#include <network/ApplicationControl.h>

using namespace ThreatOne::Network;

TEST_CASE("ApplicationControl - default policy is Allow") {
    ApplicationControl control;
    CHECK(control.getDefaultPolicy() == AppPolicy::Allow);
}

TEST_CASE("ApplicationControl - set default policy") {
    ApplicationControl control;
    control.setDefaultPolicy(AppPolicy::Deny);
    CHECK(control.getDefaultPolicy() == AppPolicy::Deny);
}

TEST_CASE("ApplicationControl - allow specific application") {
    ApplicationControl control;
    control.setDefaultPolicy(AppPolicy::Deny);
    control.allowApplication("/usr/bin/firefox");

    CHECK(control.isAllowed("/usr/bin/firefox"));
}

TEST_CASE("ApplicationControl - deny specific application") {
    ApplicationControl control;
    control.setDefaultPolicy(AppPolicy::Allow);
    control.denyApplication("/usr/bin/malware");

    CHECK_FALSE(control.isAllowed("/usr/bin/malware"));
}

TEST_CASE("ApplicationControl - default policy applies to unknown apps") {
    ApplicationControl control;
    control.setDefaultPolicy(AppPolicy::Allow);
    CHECK(control.isAllowed("/usr/bin/unknown"));

    control.setDefaultPolicy(AppPolicy::Deny);
    CHECK_FALSE(control.isAllowed("/usr/bin/unknown"));
}

TEST_CASE("ApplicationControl - remove policy resets to default") {
    ApplicationControl control;
    control.setDefaultPolicy(AppPolicy::Deny);
    control.allowApplication("/usr/bin/app");

    CHECK(control.isAllowed("/usr/bin/app"));

    control.removeApplication("/usr/bin/app");
    CHECK_FALSE(control.isAllowed("/usr/bin/app"));
}

TEST_CASE("ApplicationControl - getPolicy returns correct policy") {
    ApplicationControl control;
    control.allowApplication("/usr/bin/good");
    control.denyApplication("/usr/bin/bad");

    auto goodPolicy = control.getPolicy("/usr/bin/good");
    REQUIRE(goodPolicy.has_value());
    CHECK(goodPolicy.value() == AppPolicy::Allow);

    auto badPolicy = control.getPolicy("/usr/bin/bad");
    REQUIRE(badPolicy.has_value());
    CHECK(badPolicy.value() == AppPolicy::Deny);

    auto noPolicy = control.getPolicy("/usr/bin/unknown");
    CHECK_FALSE(noPolicy.has_value());
}

TEST_CASE("ApplicationControl - getAllPolicies returns all entries") {
    ApplicationControl control;
    control.allowApplication("/app1");
    control.denyApplication("/app2");
    control.allowApplication("/app3");

    auto policies = control.getAllPolicies();
    CHECK(policies.size() == 3);
}

TEST_CASE("ApplicationControl - overwrite existing policy") {
    ApplicationControl control;
    control.allowApplication("/usr/bin/app");
    CHECK(control.isAllowed("/usr/bin/app"));

    control.denyApplication("/usr/bin/app");
    CHECK_FALSE(control.isAllowed("/usr/bin/app"));
}
