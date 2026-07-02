#include <doctest/doctest.h>
#include <fleet/DeploymentManager.h>
#include <string>
#include <vector>

using namespace ThreatOne::Fleet;

TEST_CASE("DeploymentManager - Create deployment") {
    DeploymentManager mgr;
    std::vector<std::string> targets = {"ep-1", "ep-2", "ep-3"};

    std::string depId = mgr.createDeployment("2.0.0", targets);
    CHECK_FALSE(depId.empty());

    auto status = mgr.getDeploymentStatus(depId);
    REQUIRE(status.has_value());
    CHECK(status->version == "2.0.0");
    CHECK(status->status == DeploymentStatus::Planned);
    CHECK(status->targetEndpoints.size() == 3);
}

TEST_CASE("DeploymentManager - Start rollout") {
    DeploymentManager mgr;
    std::string depId = mgr.createDeployment("2.0.0", {"ep-1", "ep-2"});

    CHECK(mgr.startRollout(depId));

    auto status = mgr.getDeploymentStatus(depId);
    REQUIRE(status.has_value());
    CHECK(status->status == DeploymentStatus::InProgress);
    CHECK(status->currentStage == 1);
}

TEST_CASE("DeploymentManager - Cannot start already started rollout") {
    DeploymentManager mgr;
    std::string depId = mgr.createDeployment("2.0.0", {"ep-1"});
    mgr.startRollout(depId);
    CHECK_FALSE(mgr.startRollout(depId));
}

TEST_CASE("DeploymentManager - Pause and resume rollout") {
    DeploymentManager mgr;
    std::string depId = mgr.createDeployment("2.0.0", {"ep-1", "ep-2"});
    mgr.startRollout(depId);

    CHECK(mgr.pauseRollout(depId));
    auto status = mgr.getDeploymentStatus(depId);
    CHECK(status->status == DeploymentStatus::Paused);

    CHECK(mgr.resumeRollout(depId));
    status = mgr.getDeploymentStatus(depId);
    CHECK(status->status == DeploymentStatus::InProgress);
}

TEST_CASE("DeploymentManager - Cannot pause planned deployment") {
    DeploymentManager mgr;
    std::string depId = mgr.createDeployment("2.0.0", {"ep-1"});
    CHECK_FALSE(mgr.pauseRollout(depId));
}

TEST_CASE("DeploymentManager - Advance stage updates versions") {
    DeploymentManager mgr;
    mgr.setEndpointVersion("ep-1", "1.0.0");
    mgr.setEndpointVersion("ep-2", "1.0.0");

    RolloutConfig config;
    config.stages = 2;
    config.autoRollbackOnFailurePercent = 80.0;

    std::string depId = mgr.createDeployment("2.0.0", {"ep-1", "ep-2"}, config);
    mgr.startRollout(depId);

    CHECK(mgr.advanceStage(depId, 1, 0));

    auto ver = mgr.getEndpointVersion("ep-1");
    REQUIRE(ver.has_value());
    CHECK(ver.value() == "2.0.0");
}

TEST_CASE("DeploymentManager - Staged rollout completes all stages") {
    DeploymentManager mgr;
    RolloutConfig config;
    config.stages = 2;
    config.autoRollbackOnFailurePercent = 80.0;

    std::string depId = mgr.createDeployment("3.0.0", {"ep-1", "ep-2"}, config);
    mgr.startRollout(depId);

    mgr.advanceStage(depId, 1, 0); // stage 1
    mgr.advanceStage(depId, 1, 0); // stage 2

    auto status = mgr.getDeploymentStatus(depId);
    REQUIRE(status.has_value());
    CHECK(status->status == DeploymentStatus::Completed);
}

TEST_CASE("DeploymentManager - Auto failure on high failure rate") {
    DeploymentManager mgr;
    RolloutConfig config;
    config.stages = 1;
    config.autoRollbackOnFailurePercent = 50.0;

    std::string depId = mgr.createDeployment("2.0.0", {"ep-1", "ep-2"}, config);
    mgr.startRollout(depId);

    // 50% failure rate triggers auto-rollback
    mgr.advanceStage(depId, 1, 1);

    auto status = mgr.getDeploymentStatus(depId);
    REQUIRE(status.has_value());
    CHECK(status->status == DeploymentStatus::Failed);
}

TEST_CASE("DeploymentManager - Rollback restores versions") {
    DeploymentManager mgr;
    mgr.setEndpointVersion("ep-1", "1.0.0");
    mgr.setEndpointVersion("ep-2", "1.0.0");

    RolloutConfig config;
    config.stages = 1;
    config.autoRollbackOnFailurePercent = 90.0;

    std::string depId = mgr.createDeployment("2.0.0", {"ep-1", "ep-2"}, config);
    mgr.startRollout(depId);
    mgr.advanceStage(depId, 2, 0);

    // Versions should be 2.0.0 now
    CHECK(mgr.getEndpointVersion("ep-1").value() == "2.0.0");

    CHECK(mgr.rollback(depId));

    auto status = mgr.getDeploymentStatus(depId);
    CHECK(status->status == DeploymentStatus::RolledBack);

    // Versions restored
    CHECK(mgr.getEndpointVersion("ep-1").value() == "1.0.0");
    CHECK(mgr.getEndpointVersion("ep-2").value() == "1.0.0");
}

TEST_CASE("DeploymentManager - Cannot rollback planned deployment") {
    DeploymentManager mgr;
    std::string depId = mgr.createDeployment("2.0.0", {"ep-1"});
    CHECK_FALSE(mgr.rollback(depId));
}

TEST_CASE("DeploymentManager - Get all deployments") {
    DeploymentManager mgr;
    mgr.createDeployment("1.0.0", {"ep-1"});
    mgr.createDeployment("2.0.0", {"ep-2"});

    auto all = mgr.getDeployments();
    CHECK(all.size() == 2);
}

TEST_CASE("DeploymentManager - Version distribution") {
    DeploymentManager mgr;
    mgr.setEndpointVersion("ep-1", "1.0.0");
    mgr.setEndpointVersion("ep-2", "1.0.0");
    mgr.setEndpointVersion("ep-3", "2.0.0");

    auto dist = mgr.getVersionDistribution();
    CHECK(dist.size() == 2);
    // Sorted by count descending
    CHECK(dist[0].version == "1.0.0");
    CHECK(dist[0].count == 2);
    CHECK(dist[1].version == "2.0.0");
    CHECK(dist[1].count == 1);
}

TEST_CASE("DeploymentManager - Get nonexistent deployment") {
    DeploymentManager mgr;
    CHECK_FALSE(mgr.getDeploymentStatus("no-such-dep").has_value());
}

TEST_CASE("DeploymentManager - Get nonexistent endpoint version") {
    DeploymentManager mgr;
    CHECK_FALSE(mgr.getEndpointVersion("no-such-ep").has_value());
}

TEST_CASE("DeploymentManager - Previous version captured from endpoints") {
    DeploymentManager mgr;
    mgr.setEndpointVersion("ep-1", "1.5.0");

    std::string depId = mgr.createDeployment("2.0.0", {"ep-1"});
    auto status = mgr.getDeploymentStatus(depId);
    REQUIRE(status.has_value());
    CHECK(status->previousVersion == "1.5.0");
    CHECK(status->rollbackVersion == "1.5.0");
}
