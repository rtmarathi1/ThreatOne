#include <doctest/doctest.h>
#include <updates/UpdateManager.h>
#include <string>

using namespace ThreatOne::Updates;

TEST_CASE("UpdateManager - Check for updates stable channel") {
    UpdateManager mgr;

    UpdateInfo stableUpdate;
    stableUpdate.version = "2.0.0";
    stableUpdate.description = "Stable release";
    stableUpdate.size = 1000;
    stableUpdate.channel = UpdateChannel::Stable;
    mgr.addAvailableUpdate(stableUpdate);

    UpdateInfo betaUpdate;
    betaUpdate.version = "2.1.0-beta";
    betaUpdate.description = "Beta release";
    betaUpdate.size = 1200;
    betaUpdate.channel = UpdateChannel::Beta;
    mgr.addAvailableUpdate(betaUpdate);

    UpdateInfo nightlyUpdate;
    nightlyUpdate.version = "2.2.0-nightly";
    nightlyUpdate.description = "Nightly build";
    nightlyUpdate.size = 1500;
    nightlyUpdate.channel = UpdateChannel::Nightly;
    mgr.addAvailableUpdate(nightlyUpdate);

    mgr.setUpdateChannel(UpdateChannel::Stable);
    auto updates = mgr.checkForUpdates();
    REQUIRE(updates.size() == 1);
    CHECK(updates[0].version == "2.0.0");
}

TEST_CASE("UpdateManager - Check for updates beta channel") {
    UpdateManager mgr;

    UpdateInfo stableUpdate;
    stableUpdate.version = "2.0.0";
    stableUpdate.channel = UpdateChannel::Stable;
    mgr.addAvailableUpdate(stableUpdate);

    UpdateInfo betaUpdate;
    betaUpdate.version = "2.1.0-beta";
    betaUpdate.channel = UpdateChannel::Beta;
    mgr.addAvailableUpdate(betaUpdate);

    UpdateInfo nightlyUpdate;
    nightlyUpdate.version = "2.2.0-nightly";
    nightlyUpdate.channel = UpdateChannel::Nightly;
    mgr.addAvailableUpdate(nightlyUpdate);

    mgr.setUpdateChannel(UpdateChannel::Beta);
    auto updates = mgr.checkForUpdates();
    CHECK(updates.size() == 2);  // stable + beta
}

TEST_CASE("UpdateManager - Check for updates nightly channel") {
    UpdateManager mgr;

    UpdateInfo stableUpdate;
    stableUpdate.version = "2.0.0";
    stableUpdate.channel = UpdateChannel::Stable;
    mgr.addAvailableUpdate(stableUpdate);

    UpdateInfo betaUpdate;
    betaUpdate.version = "2.1.0-beta";
    betaUpdate.channel = UpdateChannel::Beta;
    mgr.addAvailableUpdate(betaUpdate);

    UpdateInfo nightlyUpdate;
    nightlyUpdate.version = "2.2.0-nightly";
    nightlyUpdate.channel = UpdateChannel::Nightly;
    mgr.addAvailableUpdate(nightlyUpdate);

    mgr.setUpdateChannel(UpdateChannel::Nightly);
    auto updates = mgr.checkForUpdates();
    CHECK(updates.size() == 3);  // all channels
}

TEST_CASE("UpdateManager - Download update") {
    UpdateManager mgr;

    UpdateInfo update;
    update.version = "2.0.0";
    update.size = 5000;
    update.channel = UpdateChannel::Stable;
    mgr.addAvailableUpdate(update);

    CHECK(mgr.downloadUpdate("2.0.0"));

    auto progress = mgr.getUpdateProgress("2.0.0");
    REQUIRE(progress.has_value());
    CHECK(progress->status == UpdateStatus::Downloaded);
    CHECK(progress->bytesDownloaded == 5000);
    CHECK(progress->totalBytes == 5000);
    CHECK(progress->percentage == doctest::Approx(100.0));
}

TEST_CASE("UpdateManager - Download nonexistent update fails") {
    UpdateManager mgr;
    CHECK_FALSE(mgr.downloadUpdate("nonexistent"));
}

TEST_CASE("UpdateManager - Install update") {
    UpdateManager mgr;
    mgr.setCurrentVersion("1.0.0");

    UpdateInfo update;
    update.version = "2.0.0";
    update.size = 5000;
    update.channel = UpdateChannel::Stable;
    mgr.addAvailableUpdate(update);

    mgr.downloadUpdate("2.0.0");
    CHECK(mgr.installUpdate("2.0.0"));

    auto version = mgr.getVersion();
    CHECK(version.current == "2.0.0");
}

TEST_CASE("UpdateManager - Install without download fails") {
    UpdateManager mgr;
    CHECK_FALSE(mgr.installUpdate("2.0.0"));
}

TEST_CASE("UpdateManager - Install incompatible update fails") {
    UpdateManager mgr;
    mgr.setCurrentVersion("1.0.0");

    UpdateInfo update;
    update.version = "5.0.0";
    update.size = 5000;
    update.channel = UpdateChannel::Stable;
    mgr.addAvailableUpdate(update);

    VersionCompatibility incompat;
    incompat.minVersion = "4.0.0";
    incompat.maxVersion = "5.0.0";
    incompat.compatible = false;
    incompat.notes = "Requires v4.0.0+";
    mgr.setCompatibilityMatrix("5.0.0", incompat);

    mgr.downloadUpdate("5.0.0");
    CHECK_FALSE(mgr.installUpdate("5.0.0"));
}

TEST_CASE("UpdateManager - Staged rollout") {
    UpdateManager mgr;

    auto rollout = mgr.stageRollout("2.0.0", 25);
    REQUIRE(rollout.has_value());
    CHECK(rollout->version == "2.0.0");
    CHECK(rollout->percentage == 25);
    CHECK(rollout->status == UpdateStatus::Installing);

    // Update rollout percentage
    auto updated = mgr.stageRollout("2.0.0", 100);
    REQUIRE(updated.has_value());
    CHECK(updated->percentage == 100);
    CHECK(updated->status == UpdateStatus::Installed);
}

TEST_CASE("UpdateManager - Staged rollout invalid percentage") {
    UpdateManager mgr;
    auto rollout = mgr.stageRollout("2.0.0", -1);
    CHECK_FALSE(rollout.has_value());

    rollout = mgr.stageRollout("2.0.0", 101);
    CHECK_FALSE(rollout.has_value());
}

TEST_CASE("UpdateManager - Rollback") {
    UpdateManager mgr;
    mgr.setCurrentVersion("1.0.0");

    UpdateInfo update;
    update.version = "2.0.0";
    update.size = 5000;
    update.channel = UpdateChannel::Stable;
    mgr.addAvailableUpdate(update);

    mgr.downloadUpdate("2.0.0");
    mgr.installUpdate("2.0.0");

    auto version = mgr.getVersion();
    CHECK(version.current == "2.0.0");

    CHECK(mgr.rollback());

    version = mgr.getVersion();
    CHECK(version.current == "1.0.0");
}

TEST_CASE("UpdateManager - Rollback without previous version fails") {
    UpdateManager mgr;
    CHECK_FALSE(mgr.rollback());
}

TEST_CASE("UpdateManager - Signature updates independent workflow") {
    UpdateManager mgr;

    SignatureUpdate sig;
    sig.id = "SIG-001";
    sig.type = "YARA";
    sig.version = "1.5.0";
    sig.size = 2048;
    sig.hash = "abc123def";
    sig.timestamp = "2024-01-15T10:00:00Z";
    mgr.addSignatureUpdate(sig);

    SignatureUpdate sig2;
    sig2.id = "SIG-002";
    sig2.type = "IOC";
    sig2.version = "2.0.0";
    sig2.size = 4096;
    sig2.hash = "xyz789";
    sig2.timestamp = "2024-01-16T10:00:00Z";
    mgr.addSignatureUpdate(sig2);

    auto signatures = mgr.getSignatureUpdates();
    CHECK(signatures.size() == 2);

    // Download and install
    CHECK(mgr.downloadSignatureUpdate("SIG-001"));
    CHECK(mgr.installSignatureUpdate("SIG-001"));

    // Cannot install without download
    CHECK_FALSE(mgr.installSignatureUpdate("SIG-002"));
}

TEST_CASE("UpdateManager - Download signature nonexistent fails") {
    UpdateManager mgr;
    CHECK_FALSE(mgr.downloadSignatureUpdate("nonexistent"));
}

TEST_CASE("UpdateManager - Install signature already installed fails") {
    UpdateManager mgr;

    SignatureUpdate sig;
    sig.id = "SIG-001";
    sig.type = "Signature";
    sig.version = "1.0.0";
    sig.size = 1024;
    mgr.addSignatureUpdate(sig);

    mgr.downloadSignatureUpdate("SIG-001");
    CHECK(mgr.installSignatureUpdate("SIG-001"));
    CHECK_FALSE(mgr.installSignatureUpdate("SIG-001"));
}

TEST_CASE("UpdateManager - Version compatibility check") {
    UpdateManager mgr;

    VersionCompatibility compat;
    compat.minVersion = "1.0.0";
    compat.maxVersion = "3.0.0";
    compat.compatible = true;
    compat.notes = "All good";
    mgr.setCompatibilityMatrix("3.0.0", compat);

    auto result = mgr.checkVersionCompatibility("3.0.0");
    CHECK(result.compatible == true);
    CHECK(result.minVersion == "1.0.0");
    CHECK(result.notes == "All good");

    // Unknown version defaults to compatible
    auto unknown = mgr.checkVersionCompatibility("99.0.0");
    CHECK(unknown.compatible == true);
}

TEST_CASE("UpdateManager - Update history tracking") {
    UpdateManager mgr;
    mgr.setCurrentVersion("1.0.0");

    UpdateInfo update;
    update.version = "2.0.0";
    update.size = 5000;
    update.channel = UpdateChannel::Stable;
    mgr.addAvailableUpdate(update);

    mgr.downloadUpdate("2.0.0");
    mgr.installUpdate("2.0.0");

    auto history = mgr.getUpdateHistory();
    REQUIRE(history.size() == 1);
    CHECK(history[0].version == "2.0.0");
    CHECK(history[0].status == UpdateStatus::Installed);
    CHECK_FALSE(history[0].timestamp.empty());
}

TEST_CASE("UpdateManager - History includes rollback") {
    UpdateManager mgr;
    mgr.setCurrentVersion("1.0.0");

    UpdateInfo update;
    update.version = "2.0.0";
    update.size = 5000;
    update.channel = UpdateChannel::Stable;
    mgr.addAvailableUpdate(update);

    mgr.downloadUpdate("2.0.0");
    mgr.installUpdate("2.0.0");
    mgr.rollback();

    auto history = mgr.getUpdateHistory();
    REQUIRE(history.size() == 2);
    CHECK(history[0].status == UpdateStatus::Installed);
    CHECK(history[1].status == UpdateStatus::RolledBack);
}

TEST_CASE("UpdateManager - Cancel update") {
    UpdateManager mgr;

    UpdateInfo update;
    update.version = "2.0.0";
    update.size = 5000;
    update.channel = UpdateChannel::Stable;
    mgr.addAvailableUpdate(update);

    mgr.downloadUpdate("2.0.0");
    CHECK(mgr.cancelUpdate("2.0.0"));

    auto progress = mgr.getUpdateProgress("2.0.0");
    CHECK_FALSE(progress.has_value());
}

TEST_CASE("UpdateManager - Cancel nonexistent update fails") {
    UpdateManager mgr;
    CHECK_FALSE(mgr.cancelUpdate("nonexistent"));
}

TEST_CASE("UpdateManager - Cancel installed update fails") {
    UpdateManager mgr;
    mgr.setCurrentVersion("1.0.0");

    UpdateInfo update;
    update.version = "2.0.0";
    update.size = 5000;
    update.channel = UpdateChannel::Stable;
    mgr.addAvailableUpdate(update);

    mgr.downloadUpdate("2.0.0");
    mgr.installUpdate("2.0.0");
    CHECK_FALSE(mgr.cancelUpdate("2.0.0"));
}

TEST_CASE("UpdateManager - Get version") {
    UpdateManager mgr;
    mgr.setCurrentVersion("1.5.0");

    UpdateInfo update;
    update.version = "2.0.0";
    update.channel = UpdateChannel::Stable;
    mgr.addAvailableUpdate(update);

    auto version = mgr.getVersion();
    CHECK(version.current == "1.5.0");
    CHECK(version.latest == "2.0.0");
    CHECK(version.updateAvailable == true);
}

TEST_CASE("UpdateManager - Get version no updates") {
    UpdateManager mgr;
    mgr.setCurrentVersion("1.0.0");

    auto version = mgr.getVersion();
    CHECK(version.current == "1.0.0");
    CHECK(version.latest == "1.0.0");
    CHECK(version.updateAvailable == false);
}

TEST_CASE("UpdateManager - Channel default is Stable") {
    UpdateManager mgr;
    CHECK(mgr.getUpdateChannel() == UpdateChannel::Stable);
}

TEST_CASE("UpdateManager - Set and get channel") {
    UpdateManager mgr;

    mgr.setUpdateChannel(UpdateChannel::Beta);
    CHECK(mgr.getUpdateChannel() == UpdateChannel::Beta);

    mgr.setUpdateChannel(UpdateChannel::Nightly);
    CHECK(mgr.getUpdateChannel() == UpdateChannel::Nightly);
}

TEST_CASE("UpdateManager - Get progress nonexistent") {
    UpdateManager mgr;
    auto progress = mgr.getUpdateProgress("nonexistent");
    CHECK_FALSE(progress.has_value());
}

TEST_CASE("UpdateManager - Signature update history tracked") {
    UpdateManager mgr;

    SignatureUpdate sig;
    sig.id = "SIG-001";
    sig.type = "YARA";
    sig.version = "1.5.0";
    sig.size = 2048;
    mgr.addSignatureUpdate(sig);

    mgr.downloadSignatureUpdate("SIG-001");
    mgr.installSignatureUpdate("SIG-001");

    auto history = mgr.getUpdateHistory();
    REQUIRE(history.size() == 1);
    CHECK(history[0].status == UpdateStatus::Installed);
    CHECK(history[0].description.find("YARA") != std::string::npos);
}
