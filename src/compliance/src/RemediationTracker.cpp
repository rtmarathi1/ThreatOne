#include "compliance/RemediationTracker.h"

#include <algorithm>
#include <chrono>
#include <sstream>

namespace ThreatOne::Compliance {

RemediationTracker::RemediationTracker()
    : logger_("RemediationTracker") {
    logger_.info("RemediationTracker initialized");
}

std::string RemediationTracker::generateId() {
    std::ostringstream oss;
    oss << "rem-" << nextId_.fetch_add(1);
    return oss.str();
}

std::string RemediationTracker::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::ctime(&time);
    std::string result = oss.str();
    if (!result.empty() && result.back() == '\n') {
        result.pop_back();
    }
    return result;
}

ThreatOne::Core::Result<RemediationItem> RemediationTracker::createItem(
    const std::string& controlId,
    Framework framework,
    const std::string& title,
    const std::string& description) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (controlId.empty()) {
        return ThreatOne::Core::Result<RemediationItem>::err(
            ThreatOne::Core::Error("Control ID cannot be empty",
                                   ThreatOne::Core::ErrorCategory::Validation));
    }

    if (title.empty()) {
        return ThreatOne::Core::Result<RemediationItem>::err(
            ThreatOne::Core::Error("Title cannot be empty",
                                   ThreatOne::Core::ErrorCategory::Validation));
    }

    RemediationItem item;
    item.id = generateId();
    item.controlId = controlId;
    item.framework = framework;
    item.title = title;
    item.description = description;
    item.status = RemediationStatus::Open;
    item.createdAt = getCurrentTimestamp();
    item.updatedAt = item.createdAt;
    item.statusHistory.push_back({RemediationStatus::Open, item.createdAt});

    items_[item.id] = item;
    logger_.info("Created remediation item {} for control {}", item.id, controlId);

    return ThreatOne::Core::Result<RemediationItem>::ok(item);
}

std::optional<RemediationItem> RemediationTracker::getItem(const std::string& itemId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = items_.find(itemId);
    if (it == items_.end()) return std::nullopt;
    return it->second;
}

std::vector<RemediationItem> RemediationTracker::getAllItems() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<RemediationItem> result;
    result.reserve(items_.size());
    for (const auto& [id, item] : items_) {
        result.push_back(item);
    }
    return result;
}

std::vector<RemediationItem> RemediationTracker::getItemsByStatus(RemediationStatus status) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<RemediationItem> result;
    for (const auto& [id, item] : items_) {
        if (item.status == status) result.push_back(item);
    }
    return result;
}

std::vector<RemediationItem> RemediationTracker::getItemsByFramework(Framework framework) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<RemediationItem> result;
    for (const auto& [id, item] : items_) {
        if (item.framework == framework) result.push_back(item);
    }
    return result;
}

std::vector<RemediationItem> RemediationTracker::getItemsByOwner(const std::string& owner) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<RemediationItem> result;
    for (const auto& [id, item] : items_) {
        if (item.owner == owner) result.push_back(item);
    }
    return result;
}

ThreatOne::Core::Result<void> RemediationTracker::assignOwner(
    const std::string& itemId, const std::string& owner) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = items_.find(itemId);
    if (it == items_.end()) {
        return ThreatOne::Core::Result<void>::err(
            ThreatOne::Core::Error("Item not found: " + itemId,
                                   ThreatOne::Core::ErrorCategory::Validation));
    }
    if (owner.empty()) {
        return ThreatOne::Core::Result<void>::err(
            ThreatOne::Core::Error("Owner cannot be empty",
                                   ThreatOne::Core::ErrorCategory::Validation));
    }
    it->second.owner = owner;
    it->second.updatedAt = getCurrentTimestamp();
    logger_.info("Assigned owner {} to item {}", owner, itemId);
    return ThreatOne::Core::Result<void>::ok();
}

ThreatOne::Core::Result<void> RemediationTracker::setDueDate(
    const std::string& itemId, const std::string& dueDate) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = items_.find(itemId);
    if (it == items_.end()) {
        return ThreatOne::Core::Result<void>::err(
            ThreatOne::Core::Error("Item not found: " + itemId,
                                   ThreatOne::Core::ErrorCategory::Validation));
    }
    if (dueDate.empty()) {
        return ThreatOne::Core::Result<void>::err(
            ThreatOne::Core::Error("Due date cannot be empty",
                                   ThreatOne::Core::ErrorCategory::Validation));
    }
    it->second.dueDate = dueDate;
    it->second.updatedAt = getCurrentTimestamp();
    logger_.info("Set due date {} for item {}", dueDate, itemId);
    return ThreatOne::Core::Result<void>::ok();
}

ThreatOne::Core::Result<void> RemediationTracker::updateStatus(
    const std::string& itemId, RemediationStatus newStatus) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = items_.find(itemId);
    if (it == items_.end()) {
        return ThreatOne::Core::Result<void>::err(
            ThreatOne::Core::Error("Item not found: " + itemId,
                                   ThreatOne::Core::ErrorCategory::Validation));
    }
    auto timestamp = getCurrentTimestamp();
    it->second.status = newStatus;
    it->second.updatedAt = timestamp;
    it->second.statusHistory.push_back({newStatus, timestamp});
    logger_.info("Updated status for item {}", itemId);
    return ThreatOne::Core::Result<void>::ok();
}

ThreatOne::Core::Result<void> RemediationTracker::addVerificationStep(
    const std::string& itemId, const std::string& step) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = items_.find(itemId);
    if (it == items_.end()) {
        return ThreatOne::Core::Result<void>::err(
            ThreatOne::Core::Error("Item not found: " + itemId,
                                   ThreatOne::Core::ErrorCategory::Validation));
    }
    if (step.empty()) {
        return ThreatOne::Core::Result<void>::err(
            ThreatOne::Core::Error("Verification step cannot be empty",
                                   ThreatOne::Core::ErrorCategory::Validation));
    }
    it->second.verificationSteps.push_back(step);
    it->second.updatedAt = getCurrentTimestamp();
    return ThreatOne::Core::Result<void>::ok();
}

std::vector<RemediationItem> RemediationTracker::checkOverdue(const std::string& currentDate) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<RemediationItem> overdueItems;

    for (auto& [id, item] : items_) {
        if (!item.dueDate.empty() &&
            item.status != RemediationStatus::Resolved &&
            item.dueDate < currentDate) {
            item.status = RemediationStatus::Overdue;
            item.updatedAt = getCurrentTimestamp();
            item.statusHistory.push_back({RemediationStatus::Overdue, item.updatedAt});
            overdueItems.push_back(item);
        }
    }

    if (!overdueItems.empty()) {
        logger_.warn("Found {} overdue remediation items", overdueItems.size());
    }
    return overdueItems;
}

ThreatOne::Core::Result<void> RemediationTracker::removeItem(const std::string& itemId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = items_.find(itemId);
    if (it == items_.end()) {
        return ThreatOne::Core::Result<void>::err(
            ThreatOne::Core::Error("Item not found: " + itemId,
                                   ThreatOne::Core::ErrorCategory::Validation));
    }
    items_.erase(it);
    logger_.info("Removed remediation item {}", itemId);
    return ThreatOne::Core::Result<void>::ok();
}

size_t RemediationTracker::getItemCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return items_.size();
}

void RemediationTracker::clearAll() {
    std::lock_guard<std::mutex> lock(mutex_);
    items_.clear();
    logger_.info("All remediation items cleared");
}

} // namespace ThreatOne::Compliance
