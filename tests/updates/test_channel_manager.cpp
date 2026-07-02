#include <doctest/doctest.h>
#include <updates/UpdateManager.h>

using namespace ThreatOne::Updates;

TEST_CASE("ChannelManager - Default channel is stable") {
    UpdateManager mgr;
    auto& cm = mgr.getChannelManager();

    CHECK(cm.getActiveChannel() == UpdateChannel::Stable);
}

TEST_CASE("ChannelManager - Set active channel") {
    UpdateManager mgr;
    auto& cm = mgr.getChannelManager();

    cm.setActiveChannel(UpdateChannel::Beta);
    CHECK(cm.getActiveChannel() == UpdateChannel::Beta);
}

TEST_CASE("ChannelManager - Default configs exist") {
    UpdateManager mgr;
    auto& cm = mgr.getChannelManager();

    auto configs = cm.getAllChannelConfigs();
    CHECK(configs.size() == 3);

    auto stableConfig = cm.getChannelConfig(UpdateChannel::Stable);
    CHECK(stableConfig.name == "Stable");
}

TEST_CASE("ChannelManager - Start rollout") {
    UpdateManager mgr;
    auto& cm = mgr.getChannelManager();

    auto id = cm.startRollout("2.0.0", UpdateChannel::Stable, 25);
    CHECK_FALSE(id.empty());

    auto rollout = cm.getRollout(id);
    REQUIRE(rollout.has_value());
    CHECK(rollout->version == "2.0.0");
    CHECK(rollout->targetPercentage == 25);
    CHECK(rollout->active == true);
}

TEST_CASE("ChannelManager - Complete rollout") {
    UpdateManager mgr;
    auto& cm = mgr.getChannelManager();

    auto id = cm.startRollout("2.0.0", UpdateChannel::Stable, 100);
    CHECK(cm.completeRollout(id));

    auto rollout = cm.getRollout(id);
    CHECK_FALSE(rollout->active);
}

TEST_CASE("ChannelManager - Cancel rollout") {
    UpdateManager mgr;
    auto& cm = mgr.getChannelManager();

    auto id = cm.startRollout("2.0.0", UpdateChannel::Stable, 50);
    CHECK(cm.cancelRollout(id));

    auto rollout = cm.getRollout(id);
    CHECK_FALSE(rollout->active);
}

TEST_CASE("ChannelManager - Invalid rollout percentage") {
    UpdateManager mgr;
    auto& cm = mgr.getChannelManager();

    CHECK(cm.startRollout("2.0.0", UpdateChannel::Stable, -1).empty());
    CHECK(cm.startRollout("2.0.0", UpdateChannel::Stable, 101).empty());
}

TEST_CASE("ChannelManager - Active rollouts") {
    UpdateManager mgr;
    auto& cm = mgr.getChannelManager();

    cm.startRollout("2.0.0", UpdateChannel::Stable, 25);
    cm.startRollout("2.1.0", UpdateChannel::Beta, 50);

    auto active = cm.getActiveRollouts();
    CHECK(active.size() == 2);
    CHECK(cm.getActiveRolloutCount() == 2);
}
