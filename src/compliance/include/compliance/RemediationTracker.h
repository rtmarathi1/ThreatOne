#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>
#include <optional>

#include "compliance/IComplianceEngine.h"
#include "core/Logger.h"
#include "core/Error.h"

namespace ThreatOne::Compliance {

class RemediationTracker {
public:
    RemediationTracker();
    ~RemediationTracker() = default;

    // Create a new remediation item
    [[nodiscard]] ThreatOne::Core::Result<RemediationItem> createItem(
        const std::string& controlId,
        Framework framework,
        const std::string& title,
        const std::string& description);

    // Get a remediation item by ID
    [[nodiscard]] std::optional<RemediationItem> getItem(const std::string& itemId) const;

    // Get all remediation items
    [[nodiscard]] std::vector<RemediationItem> getAllItems() const;

    // Get items by status
    [[nodiscard]] std::vector<RemediationItem> getItemsByStatus(RemediationStatus status) const;

    // Get items by framework
    [[nodiscard]] std::vector<RemediationItem> getItemsByFramework(Framework framework) const;

    // Get items by owner
    [[nodiscard]] std::vector<RemediationItem> getItemsByOwner(const std::string& owner) const;

    // Assign owner to an item
    [[nodiscard]] ThreatOne::Core::Result<void> assignOwner(
        const std::string& itemId, const std::string& owner);

    // Set due date for an item
    [[nodiscard]] ThreatOne::Core::Result<void> setDueDate(
        const std::string& itemId, const std::string& dueDate);

    // Update status of an item
    [[nodiscard]] ThreatOne::Core::Result<void> updateStatus(
        const std::string& itemId, RemediationStatus newStatus);

    // Add verification steps to an item
    [[nodiscard]] ThreatOne::Core::Result<void> addVerificationStep(
        const std::string& itemId, const std::string& step);

    // Check for overdue items and mark them
    [[nodiscard]] std::vector<RemediationItem> checkOverdue(const std::string& currentDate);

    // Remove an item
    [[nodiscard]] ThreatOne::Core::Result<void> removeItem(const std::string& itemId);

    // Get total item count
    [[nodiscard]] size_t getItemCount() const;

    // Clear all items
    void clearAll();

private:
    [[nodiscard]] std::string generateId();
    [[nodiscard]] std::string getCurrentTimestamp() const;

    mutable std::mutex mutex_;
    std::map<std::string, RemediationItem> items_;
    std::atomic<int> nextId_{1};
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Compliance
