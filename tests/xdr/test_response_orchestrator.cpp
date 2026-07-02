#include <doctest/doctest.h>
#include <xdr/ResponseOrchestrator.h>
#include <string>
#include <vector>

using namespace ThreatOne::XDR;

TEST_CASE("ResponseOrchestrator - Execute action with valid target") {
    ResponseOrchestrator ro;

    ResponseAction action;
    action.type = ActionType::IsolateEndpoint;
    action.target = "EP-001";

    std::string id = ro.executeAction(action);
    CHECK_FALSE(id.empty());
    CHECK(ro.getTotalExecuted() == 1);

    auto executed = ro.getExecutedActions();
    REQUIRE(executed.size() == 1);
    CHECK(executed[0].status == ActionStatus::Completed);
    CHECK(executed[0].target == "EP-001");
}

TEST_CASE("ResponseOrchestrator - Execute action with empty target fails") {
    ResponseOrchestrator ro;

    ResponseAction action;
    action.type = ActionType::BlockIP;
    action.target = "";

    std::string id = ro.executeAction(action);
    CHECK_FALSE(id.empty());

    auto a = ro.getAction(id);
    CHECK(a.status == ActionStatus::Failed);
    CHECK(ro.getFailedCount() == 1);
}

TEST_CASE("ResponseOrchestrator - Queue actions by priority") {
    ResponseOrchestrator ro;

    ResponseAction lowPriority;
    lowPriority.type = ActionType::BlockIP;
    lowPriority.target = "1.2.3.4";
    ro.queueAction(lowPriority, 1);

    ResponseAction highPriority;
    highPriority.type = ActionType::IsolateEndpoint;
    highPriority.target = "EP-001";
    ro.queueAction(highPriority, 10);

    CHECK(ro.getQueueSize() == 2);

    auto queue = ro.getActionQueue();
    REQUIRE(queue.size() == 2);
    // Higher priority should be first
    CHECK(queue[0].priority == 10);
    CHECK(queue[1].priority == 1);
}

TEST_CASE("ResponseOrchestrator - Process next action from queue") {
    ResponseOrchestrator ro;

    ResponseAction action;
    action.type = ActionType::KillProcess;
    action.target = "malware.exe";
    ro.queueAction(action, 5);

    CHECK(ro.getQueueSize() == 1);
    std::string processedId = ro.processNextAction();
    CHECK_FALSE(processedId.empty());
    CHECK(ro.getQueueSize() == 0);
    CHECK(ro.getTotalExecuted() == 1);
}

TEST_CASE("ResponseOrchestrator - Process empty queue returns empty") {
    ResponseOrchestrator ro;
    std::string result = ro.processNextAction();
    CHECK(result.empty());
}

TEST_CASE("ResponseOrchestrator - Approval workflow") {
    ResponseOrchestrator ro;

    ResponseAction action;
    action.type = ActionType::DisableUser;
    action.target = "compromised_user";
    ro.queueAction(action, 5, true);  // Requires approval

    // Cannot process without approval
    std::string result = ro.processNextAction();
    CHECK(result.empty());
    CHECK(ro.getQueueSize() == 1);

    // Request approval
    auto queue = ro.getActionQueue();
    std::string approvalId = ro.requestApproval(queue[0].action.id, "analyst1");
    CHECK_FALSE(approvalId.empty());
    CHECK(ro.getPendingApprovalCount() == 1);

    // Approve
    CHECK(ro.approveAction(approvalId, "manager1"));
    CHECK(ro.getPendingApprovalCount() == 0);

    // Now can process
    result = ro.processNextAction();
    CHECK_FALSE(result.empty());
    CHECK(ro.getQueueSize() == 0);
}

TEST_CASE("ResponseOrchestrator - Deny action removes from queue") {
    ResponseOrchestrator ro;

    ResponseAction action;
    action.type = ActionType::IsolateEndpoint;
    action.target = "EP-001";
    ro.queueAction(action, 5, true);

    auto queue = ro.getActionQueue();
    std::string approvalId = ro.requestApproval(queue[0].action.id, "analyst1");

    CHECK(ro.denyAction(approvalId, "Not authorized"));
    CHECK(ro.getQueueSize() == 0);
}

TEST_CASE("ResponseOrchestrator - Rollback action") {
    ResponseOrchestrator ro;

    ResponseAction action;
    action.type = ActionType::IsolateEndpoint;
    action.target = "EP-001";
    std::string actionId = ro.executeAction(action);

    std::string rollbackId = ro.rollbackAction(actionId);
    CHECK_FALSE(rollbackId.empty());

    auto history = ro.getRollbackHistory();
    REQUIRE(history.size() == 1);
    CHECK(history[0].originalActionId == actionId);
    CHECK(history[0].successful);
    CHECK(history[0].target == "EP-001");
}

TEST_CASE("ResponseOrchestrator - Rollback nonexistent action returns empty") {
    ResponseOrchestrator ro;
    std::string result = ro.rollbackAction("nonexistent");
    CHECK(result.empty());
}

TEST_CASE("ResponseOrchestrator - Multiple actions") {
    ResponseOrchestrator ro;

    ResponseAction a1;
    a1.type = ActionType::BlockIP;
    a1.target = "1.2.3.4";
    ro.executeAction(a1);

    ResponseAction a2;
    a2.type = ActionType::DisableUser;
    a2.target = "attacker";
    ro.executeAction(a2);

    ResponseAction a3;
    a3.type = ActionType::KillProcess;
    a3.target = "malware.exe";
    ro.executeAction(a3);

    CHECK(ro.getTotalExecuted() == 3);
    CHECK(ro.getFailedCount() == 0);
}

TEST_CASE("ResponseOrchestrator - Get pending approvals") {
    ResponseOrchestrator ro;

    ResponseAction action;
    action.type = ActionType::IsolateEndpoint;
    action.target = "EP-001";
    ro.queueAction(action, 5, true);

    auto queue = ro.getActionQueue();
    ro.requestApproval(queue[0].action.id, "analyst1");

    auto pending = ro.getPendingApprovals();
    REQUIRE(pending.size() == 1);
    CHECK(pending[0].requestedBy == "analyst1");
    CHECK(pending[0].status == "pending");
}
