#include <doctest/doctest.h>
#include <updates/UpdateManager.h>

using namespace ThreatOne::Updates;

TEST_CASE("DeltaUpdater - Create delta patch") {
    UpdateManager mgr;
    auto& du = mgr.getDeltaUpdater();

    auto id = du.createDeltaPatch("1.0.0", "1.1.0", 500, 5000);
    CHECK_FALSE(id.empty());
    CHECK(id.find("PATCH-") == 0);

    auto patch = du.getDeltaPatch(id);
    REQUIRE(patch.has_value());
    CHECK(patch->fromVersion == "1.0.0");
    CHECK(patch->toVersion == "1.1.0");
    CHECK(patch->patchSize == 500);
    CHECK(patch->fullSize == 5000);
}

TEST_CASE("DeltaUpdater - Find patch") {
    UpdateManager mgr;
    auto& du = mgr.getDeltaUpdater();

    du.createDeltaPatch("1.0.0", "1.1.0", 500, 5000);
    du.createDeltaPatch("1.1.0", "1.2.0", 300, 4000);

    auto found = du.findPatch("1.0.0", "1.1.0");
    REQUIRE(found.has_value());
    CHECK(found->patchSize == 500);

    auto notFound = du.findPatch("1.0.0", "2.0.0");
    CHECK_FALSE(notFound.has_value());
}

TEST_CASE("DeltaUpdater - Apply unverified patch fails") {
    UpdateManager mgr;
    auto& du = mgr.getDeltaUpdater();

    auto id = du.createDeltaPatch("1.0.0", "1.1.0", 500, 5000);
    auto result = du.applyDelta(id);
    CHECK_FALSE(result.success);
    CHECK(result.errorMessage == "Patch not verified");
}

TEST_CASE("DeltaUpdater - Apply verified patch succeeds") {
    UpdateManager mgr;
    auto& du = mgr.getDeltaUpdater();

    auto id = du.createDeltaPatch("1.0.0", "1.1.0", 500, 5000);
    CHECK(du.verifyPatch(id, "sha256:abc"));

    auto result = du.applyDelta(id);
    CHECK(result.success == true);
    CHECK(result.fromVersion == "1.0.0");
    CHECK(result.toVersion == "1.1.0");
    CHECK(result.bytesApplied == 500);
}

TEST_CASE("DeltaUpdater - Calculate savings") {
    UpdateManager mgr;
    auto& du = mgr.getDeltaUpdater();

    auto id = du.createDeltaPatch("1.0.0", "1.1.0", 1000, 10000);
    double savings = du.calculateSavingsPercentage(id);
    CHECK(savings == doctest::Approx(90.0));
}

TEST_CASE("DeltaUpdater - Statistics") {
    UpdateManager mgr;
    auto& du = mgr.getDeltaUpdater();

    auto id = du.createDeltaPatch("1.0.0", "1.1.0", 500, 5000);
    du.verifyPatch(id, "hash");
    du.applyDelta(id);

    CHECK(du.getTotalPatchesApplied() == 1);
    CHECK(du.getTotalBytesSaved() == 4500);
    CHECK(du.getPatchCount() == 1);
}
