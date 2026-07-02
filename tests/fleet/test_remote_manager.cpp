#include <doctest/doctest.h>
#include <fleet/RemoteManager.h>
#include <string>

using namespace ThreatOne::Fleet;

TEST_CASE("RemoteManager - Execute command") {
    RemoteManager mgr;
    std::string cmdId = mgr.executeCommand("ep-1", CommandType::Scan, "full");
    CHECK_FALSE(cmdId.empty());

    auto status = mgr.getCommandStatus(cmdId);
    REQUIRE(status.has_value());
    CHECK(status->endpointId == "ep-1");
    CHECK(status->type == CommandType::Scan);
    CHECK(status->status == CommandStatus::Queued);
    CHECK(status->parameters == "full");
}

TEST_CASE("RemoteManager - Command appears in queue") {
    RemoteManager mgr;
    std::string cmdId = mgr.executeCommand("ep-1", CommandType::Restart);

    auto queue = mgr.getCommandQueue("ep-1");
    CHECK(queue.size() == 1);
    CHECK(queue[0].id == cmdId);
}

TEST_CASE("RemoteManager - Multiple commands for same endpoint") {
    RemoteManager mgr;
    mgr.executeCommand("ep-1", CommandType::Scan);
    mgr.executeCommand("ep-1", CommandType::Update);

    auto queue = mgr.getCommandQueue("ep-1");
    CHECK(queue.size() == 2);
}

TEST_CASE("RemoteManager - Cancel queued command") {
    RemoteManager mgr;
    std::string cmdId = mgr.executeCommand("ep-1", CommandType::Scan);

    CHECK(mgr.cancelCommand(cmdId));

    auto status = mgr.getCommandStatus(cmdId);
    REQUIRE(status.has_value());
    CHECK(status->status == CommandStatus::Cancelled);
}

TEST_CASE("RemoteManager - Cannot cancel completed command") {
    RemoteManager mgr;
    std::string cmdId = mgr.executeCommand("ep-1", CommandType::Scan);

    CommandResult result;
    result.success = true;
    result.output = "Scan complete";
    result.exitCode = 0;
    mgr.completeCommand(cmdId, result);

    CHECK_FALSE(mgr.cancelCommand(cmdId));
}

TEST_CASE("RemoteManager - Complete command with success") {
    RemoteManager mgr;
    std::string cmdId = mgr.executeCommand("ep-1", CommandType::Scan);

    CommandResult result;
    result.success = true;
    result.output = "No threats found";
    result.exitCode = 0;

    CHECK(mgr.completeCommand(cmdId, result));

    auto status = mgr.getCommandStatus(cmdId);
    REQUIRE(status.has_value());
    CHECK(status->status == CommandStatus::Completed);
    CHECK(status->result.output == "No threats found");
    CHECK(status->result.exitCode == 0);
}

TEST_CASE("RemoteManager - Complete command with failure") {
    RemoteManager mgr;
    std::string cmdId = mgr.executeCommand("ep-1", CommandType::Update);

    CommandResult result;
    result.success = false;
    result.errorMessage = "Insufficient disk space";
    result.exitCode = 1;

    CHECK(mgr.completeCommand(cmdId, result));

    auto status = mgr.getCommandStatus(cmdId);
    REQUIRE(status.has_value());
    CHECK(status->status == CommandStatus::Failed);
    CHECK(status->result.errorMessage == "Insufficient disk space");
}

TEST_CASE("RemoteManager - Cannot complete already completed command") {
    RemoteManager mgr;
    std::string cmdId = mgr.executeCommand("ep-1", CommandType::Scan);

    CommandResult result;
    result.success = true;
    mgr.completeCommand(cmdId, result);

    CommandResult result2;
    result2.success = false;
    CHECK_FALSE(mgr.completeCommand(cmdId, result2));
}

TEST_CASE("RemoteManager - Get status of nonexistent command") {
    RemoteManager mgr;
    CHECK_FALSE(mgr.getCommandStatus("no-such-cmd").has_value());
}

TEST_CASE("RemoteManager - Cancel nonexistent command returns false") {
    RemoteManager mgr;
    CHECK_FALSE(mgr.cancelCommand("no-such-cmd"));
}

TEST_CASE("RemoteManager - Push config creates ConfigPush command") {
    RemoteManager mgr;
    ConfigPayload config;
    config.configName = "firewall_rules";
    config.configData = "{\"block\": [\"10.0.0.0/8\"]}";
    config.version = 2;

    std::string cmdId = mgr.pushConfig("ep-1", config);
    CHECK_FALSE(cmdId.empty());

    auto status = mgr.getCommandStatus(cmdId);
    REQUIRE(status.has_value());
    CHECK(status->type == CommandType::ConfigPush);
    CHECK(status->parameters.find("firewall_rules") != std::string::npos);
}

TEST_CASE("RemoteManager - Trigger remote scan") {
    RemoteManager mgr;
    std::string cmdId = mgr.triggerRemoteScan("ep-1", "quick");
    CHECK_FALSE(cmdId.empty());

    auto status = mgr.getCommandStatus(cmdId);
    REQUIRE(status.has_value());
    CHECK(status->type == CommandType::Scan);
    CHECK(status->parameters.find("quick") != std::string::npos);
}

TEST_CASE("RemoteManager - Get command history includes all statuses") {
    RemoteManager mgr;
    std::string cmd1 = mgr.executeCommand("ep-1", CommandType::Scan);
    std::string cmd2 = mgr.executeCommand("ep-1", CommandType::Restart);

    CommandResult result;
    result.success = true;
    mgr.completeCommand(cmd1, result);

    auto history = mgr.getCommandHistory("ep-1");
    CHECK(history.size() == 2);
}

TEST_CASE("RemoteManager - Completed commands not in active queue") {
    RemoteManager mgr;
    std::string cmd1 = mgr.executeCommand("ep-1", CommandType::Scan);
    std::string cmd2 = mgr.executeCommand("ep-1", CommandType::Restart);

    CommandResult result;
    result.success = true;
    mgr.completeCommand(cmd1, result);

    auto queue = mgr.getCommandQueue("ep-1");
    CHECK(queue.size() == 1);
    CHECK(queue[0].id == cmd2);
}

TEST_CASE("RemoteManager - Empty queue for unknown endpoint") {
    RemoteManager mgr;
    auto queue = mgr.getCommandQueue("unknown-ep");
    CHECK(queue.empty());
}
