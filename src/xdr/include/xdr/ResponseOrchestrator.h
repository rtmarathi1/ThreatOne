#pragma once

#include "xdr/IXDREngine.h"
#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>
#include <deque>

namespace ThreatOne::XDR {

// Represents an approval request for a response action
struct ApprovalRequest {
    std::string id;
    std::string actionId;
    std::string requestedBy;
    std::string approvedBy;
    std::string status;  // "pending", "approved", "denied"
    std::string reason;
    std::string timestamp;
};

// Represents a rollback record
struct RollbackRecord {
    std::string id;
    std::string originalActionId;
    ActionType originalAction;
    std::string target;
    std::string rollbackTimestamp;
    bool successful = false;
};

// Represents an action in the queue
struct QueuedAction {
    std::string id;
    ResponseAction action;
    int priority = 0;  // Higher = more urgent
    bool requiresApproval = false;
    std::string queuedTimestamp;
};

class ResponseOrchestrator {
public:
    ResponseOrchestrator();
    ~ResponseOrchestrator() = default;

    // Action execution
    std::string executeAction(const ResponseAction& action);
    [[nodiscard]] std::vector<ResponseAction> getExecutedActions() const;
    [[nodiscard]] ResponseAction getAction(const std::string& actionId) const;

    // Action queue management
    std::string queueAction(const ResponseAction& action, int priority = 0, bool requiresApproval = false);
    [[nodiscard]] std::vector<QueuedAction> getActionQueue() const;
    std::string processNextAction();
    [[nodiscard]] size_t getQueueSize() const;

    // Approval workflow
    std::string requestApproval(const std::string& actionId, const std::string& requestedBy);
    bool approveAction(const std::string& approvalId, const std::string& approvedBy);
    bool denyAction(const std::string& approvalId, const std::string& reason);
    [[nodiscard]] std::vector<ApprovalRequest> getPendingApprovals() const;

    // Rollback support
    std::string rollbackAction(const std::string& actionId);
    [[nodiscard]] std::vector<RollbackRecord> getRollbackHistory() const;

    // Stats
    [[nodiscard]] size_t getTotalExecuted() const;
    [[nodiscard]] size_t getFailedCount() const;
    [[nodiscard]] size_t getPendingApprovalCount() const;

private:
    std::string generateActionId();
    std::string generateApprovalId();
    std::string generateRollbackId();
    std::string generateQueueId();
    std::string getCurrentTimestamp() const;

    mutable std::mutex mutex_;
    std::map<std::string, ResponseAction> executedActions_;
    std::deque<QueuedAction> actionQueue_;
    std::map<std::string, ApprovalRequest> approvalRequests_;
    std::map<std::string, RollbackRecord> rollbacks_;
    int nextActionId_ = 1;
    int nextApprovalId_ = 1;
    int nextRollbackId_ = 1;
    int nextQueueId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::XDR
