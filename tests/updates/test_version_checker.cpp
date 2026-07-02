#include <doctest/doctest.h>
#include <updates/UpdateManager.h>

using namespace ThreatOne::Updates;

TEST_CASE("VersionChecker - Compare versions") {
    UpdateManager mgr;
    auto& vc = mgr.getVersionChecker();

    CHECK(vc.compareVersions("1.0.0", "1.0.0") == 0);
    CHECK(vc.compareVersions("1.0.0", "2.0.0") == -1);
    CHECK(vc.compareVersions("2.0.0", "1.0.0") == 1);
    CHECK(vc.compareVersions("1.2.3", "1.2.4") == -1);
    CHECK(vc.compareVersions("1.10.0", "1.9.0") == 1);
}

TEST_CASE("VersionChecker - Is newer version") {
    UpdateManager mgr;
    auto& vc = mgr.getVersionChecker();

    CHECK(vc.isNewerVersion("2.0.0", "1.0.0"));
    CHECK_FALSE(vc.isNewerVersion("1.0.0", "2.0.0"));
    CHECK_FALSE(vc.isNewerVersion("1.0.0", "1.0.0"));
}

TEST_CASE("VersionChecker - Version compatibility range") {
    UpdateManager mgr;
    auto& vc = mgr.getVersionChecker();

    CHECK(vc.isCompatibleVersion("1.5.0", "1.0.0", "2.0.0"));
    CHECK(vc.isCompatibleVersion("1.0.0", "1.0.0", "2.0.0"));
    CHECK_FALSE(vc.isCompatibleVersion("0.9.0", "1.0.0", "2.0.0"));
    CHECK_FALSE(vc.isCompatibleVersion("2.1.0", "1.0.0", "2.0.0"));
}

TEST_CASE("VersionChecker - Check for updates by channel") {
    UpdateManager mgr;
    auto& vc = mgr.getVersionChecker();

    UpdateInfo stable;
    stable.version = "2.0.0";
    stable.channel = UpdateChannel::Stable;
    vc.addAvailableUpdate(stable);

    UpdateInfo beta;
    beta.version = "2.1.0-beta";
    beta.channel = UpdateChannel::Beta;
    vc.addAvailableUpdate(beta);

    auto stableUpdates = vc.checkForUpdates(UpdateChannel::Stable);
    CHECK(stableUpdates.size() == 1);

    auto betaUpdates = vc.checkForUpdates(UpdateChannel::Beta);
    CHECK(betaUpdates.size() == 2);
}

TEST_CASE("VersionChecker - Get latest for channel") {
    UpdateManager mgr;
    auto& vc = mgr.getVersionChecker();

    UpdateInfo v1;
    v1.version = "1.5.0";
    v1.channel = UpdateChannel::Stable;
    vc.addAvailableUpdate(v1);

    UpdateInfo v2;
    v2.version = "2.0.0";
    v2.channel = UpdateChannel::Stable;
    vc.addAvailableUpdate(v2);

    auto latest = vc.getLatestForChannel(UpdateChannel::Stable);
    REQUIRE(latest.has_value());
    CHECK(latest->version == "2.0.0");
}

TEST_CASE("VersionChecker - Perform update check") {
    UpdateManager mgr;
    auto& vc = mgr.getVersionChecker();

    auto result = vc.performUpdateCheck(UpdateChannel::Stable);
    CHECK(result.success == true);
    CHECK(vc.getTotalChecks() == 1);
    CHECK_FALSE(vc.getLastCheckTime().empty());
}
