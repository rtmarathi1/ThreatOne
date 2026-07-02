#include "xdr/ResponseOrchestrator.h"
#include <mutex>

#include <algorithm>
#include <sstream>
#include <ctime>
#include <iomanip>

namespace ThreatOne::XDR {

ResponseOrchestrator::ResponseOrchestrator()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("ResponseOrchestrator")) {
    logger_.info("ResponseOrchestrator initialized");
}

std::string ResponseOrchestrator::generateActionId() {
    return "ACT-" + std::to_string(nextActionId_++);
}

std::string ResponseOrchestrator::generateApprovalId() {
    return "APPR-" + std::to_string(nextApprovalId_++);
}

std::string ResponseOrchestrator::generateRollbackId() {
    return "ROLLBACK-" + std::to_string(nextRollbackId_++);
}

std::string ResponseOrchestrator::generateQueueId() {
    return "QUEUE-" + std::to_string(nextQueueId_++);
}

std::string ResponseOrchestrator::getCurrentTimestamp() const {
    auto now = std::time(nullptr);
    std::tm tm = {};
#ifdef _WIN32
    gmtime_s(&tm, &now);
#else
    gmtime_r(&now, &tm);
#endif
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
    return ss.str();
}

std::string ResponseOrchestrator::executeAction(const ResponseAction& action) {
    std::lock_guard<std::mutex> lock(mutex_);

    ResponseAction stored = action;
    stored.id = action.id.empty() ? generateActionId() : action.id;
    stored.status = ActionStatus::Completed;

    if (stored.target.empty()) {
        stored.status = ActionStatus::Failed;
        logger_.warn("Response action failed: empty target");
    } else {
        logger_.info("Executed response action: id={}, type={}, target={}",
                     stored.id, static_cast<int>(stored.type), stored.target);
    }

    executedActions_[stored.id] = stored;
    return stored.id;
}

std::vector<ResponseAction> ResponseOrchestrator::getExecutedActions() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ResponseAction> result;
    result.reserve(executedActions_.size());
    for (const auto& [id, action] : executedActions_) {
        result.push_back(action);
    }
    return result;
}

ResponseAction ResponseOrchestrator::getAction(const std::string& actionId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = executedActions_.find(actionId);
    if (it != executedActions_.end()) {
        return it->second;
    }
    return ResponseAction{};
}

std::string ResponseOrchestrator::queueAction(const ResponseAction& action, int priority, bool requiresApproval) {
    std::lock_guard<std::mutex> lock(mutex_);

    QueuedAction queued;
    queued.id = generateQueueId();
    queued.action = action;
    if (queued.action.id.empty()) {
        queued.action.id = generateActionId();
    }
    queued.priority = priority;
    queued.requiresApproval = requiresApproval;
    queued.queuedTimestamp = getCurrentTimestamp();

    // Insert in priority order (higher priority first)
    auto insertPos = std::find_if(actionQueue_.begin(), actionQueue_.end(),
        [priority](const QueuedAction& q) { return q.priority < priority; });
    actionQueue_.insert(insertPos, queued);

    logger_.info("Queued action: id={}, priority={}, requiresApproval={}",
                 queued.id, priority, requiresApproval);
    return queued.id;
}

std::vector<QueuedAction> ResponseOrchestrator::getActionQueue() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::vector<QueuedAction>(actionQueue_.begin(), actionQueue_.end());
}

std::string ResponseOrchestrator::processNextAction() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (actionQueue_.empty()) {
        return "";
    }

    // Find first action that does not require approval (or is already approved)
    for (auto it = actionQueue_.begin(); it != actionQueue_.end(); ++it) {
        if (!it->requiresApproval) {
            ResponseAction action = it->action;
            actionQueue_.erase(it);

            action.status = ActionStatus::Completed;
            if (action.target.empty()) {
                action.status = ActionStatus::Failed;
            }
            executedActions_[action.id] = action;

            logger_.info("Processed queued action: id={}", action.id);
            return action.id;
        }
    }

    return "";
}

size_t ResponseOrchestrator::getQueueSize() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return actionQueue_.size();
}

std::string ResponseOrchestrator::requestApproval(const std::string& actionId, const std::string& requestedBy) {
    std::lock_guard<std::mutex> lock(mutex_);

    ApprovalRequest request;
    request.id = generateApprovalId();
    request.actionId = actionId;
    request.requestedBy = requestedBy;
    request.status = "pending";
    request.timestamp = getCurrentTimestamp();

    approvalRequests_[request.id] = request;
    logger_.info("Approval requested: id={}, action={}, by={}", request.id, actionId, requestedBy);
    return request.id;
}

bool ResponseOrchestrator::approveAction(const std::string& approvalId, const std::string& approvedBy) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = approvalRequests_.find(approvalId);
    if (it == approvalRequests_.end() || it->second.status != "pending") {
        return false;
    }

    it->second.status = "approved";
    it->second.approvedBy = approvedBy;

    // Find and remove approval requirement from queue
    for (auto& queued : actionQueue_) {
        if (queued.action.id == it->second.actionId) {
            queued.requiresApproval = false;
        }
    }

    logger_.info("Action approved: approval={}, by={}", approvalId, approvedBy);
    return true;
}

bool ResponseOrchestrator::denyAction(const std::string& approvalId, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = approvalRequests_.find(approvalId);
    if (it == approvalRequests_.end() || it->second.status != "pending") {
        return false;
    }

    it->second.status = "denied";
    it->second.reason = reason;

    // Remove from queue
    auto queueIt = std::find_if(actionQueue_.begin(), actionQueue_.end(),
        [&](const QueuedAction& q) { return q.action.id == it->second.actionId; });
    if (queueIt != actionQueue_.end()) {
        actionQueue_.erase(queueIt);
    }

    logger_.info("Action denied: approval={}, reason={}", approvalId, reason);
    return true;
}

std::vector<ApprovalRequest> ResponseOrchestrator::getPendingApprovals() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ApprovalRequest> result;
    for (const auto& [id, req] : approvalRequests_) {
        if (req.status == "pending") {
            result.push_back(req);
        }
    }
    return result;
}

std::string ResponseOrchestrator::rollbackAction(const std::string& actionId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = executedActions_.find(actionId);
    if (it == executedActions_.end()) {
        return "";
    }

    RollbackRecord record;
    record.id = generateRollbackId();
    record.originalActionId = actionId;
    record.originalAction = it->second.type;
    record.target = it->second.target;
    record.rollbackTimestamp = getCurrentTimestamp();
    record.successful = true;

    rollbacks_[record.id] = record;
    logger_.info("Rolled back action: id={}, original={}", record.id, actionId);
    return record.id;
}

std::vector<RollbackRecord> ResponseOrchestrator::getRollbackHistory() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<RollbackRecord> result;
    result.reserve(rollbacks_.size());
    for (const auto& [id, record] : rollbacks_) {
        result.push_back(record);
    }
    return result;
}

size_t ResponseOrchestrator::getTotalExecuted() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return executedActions_.size();
}

size_t ResponseOrchestrator::getFailedCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& [id, action] : executedActions_) {
        if (action.status == ActionStatus::Failed) {
            count++;
        }
    }
    return count;
}

size_t ResponseOrchestrator::getPendingApprovalCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& [id, req] : approvalRequests_) {
        if (req.status == "pending") {
            count++;
        }
    }
    return count;
}

} // namespace ThreatOne::XDR
