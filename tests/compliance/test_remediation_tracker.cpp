#include <doctest/doctest.h>
#include <compliance/RemediationTracker.h>

using namespace ThreatOne::Compliance;

TEST_CASE("RemediationTracker - create item") {
    RemediationTracker tracker;

    auto result = tracker.createItem(
        "NIST-ID-1", Framework::NIST,
        "Fix access control", "Implement proper access control mechanisms");
    REQUIRE(result.isOk());

    auto item = result.value();
    CHECK_FALSE(item.id.empty());
    CHECK(item.controlId == "NIST-ID-1");
    CHECK(item.framework == Framework::NIST);
    CHECK(item.title == "Fix access control");
    CHECK(item.description == "Implement proper access control mechanisms");
    CHECK(item.status == RemediationStatus::Open);
    CHECK_FALSE(item.createdAt.empty());
    CHECK_FALSE(item.updatedAt.empty());
    CHECK(item.statusHistory.size() == 1);
}

TEST_CASE("RemediationTracker - get item by ID") {
    RemediationTracker tracker;

    auto result = tracker.createItem("C1", Framework::NIST, "Item 1", "Desc");
    REQUIRE(result.isOk());

    auto found = tracker.getItem(result.value().id);
    REQUIRE(found.has_value());
    CHECK(found->title == "Item 1");

    auto notFound = tracker.getItem("nonexistent");
    CHECK_FALSE(notFound.has_value());
}

TEST_CASE("RemediationTracker - get all items") {
    RemediationTracker tracker;

    (void)tracker.createItem("C1", Framework::NIST, "Item 1", "D1");
    (void)tracker.createItem("C2", Framework::SOC2, "Item 2", "D2");
    (void)tracker.createItem("C3", Framework::HIPAA, "Item 3", "D3");

    auto all = tracker.getAllItems();
    CHECK(all.size() == 3);
    CHECK(tracker.getItemCount() == 3);
}

TEST_CASE("RemediationTracker - get items by status") {
    RemediationTracker tracker;

    auto r1 = tracker.createItem("C1", Framework::NIST, "Item 1", "D1");
    auto r2 = tracker.createItem("C2", Framework::NIST, "Item 2", "D2");
    REQUIRE(r1.isOk());
    REQUIRE(r2.isOk());

    (void)tracker.updateStatus(r1.value().id, RemediationStatus::InProgress);

    auto openItems = tracker.getItemsByStatus(RemediationStatus::Open);
    CHECK(openItems.size() == 1);

    auto inProgress = tracker.getItemsByStatus(RemediationStatus::InProgress);
    CHECK(inProgress.size() == 1);
}

TEST_CASE("RemediationTracker - get items by framework") {
    RemediationTracker tracker;

    (void)tracker.createItem("C1", Framework::NIST, "Item 1", "D1");
    (void)tracker.createItem("C2", Framework::NIST, "Item 2", "D2");
    (void)tracker.createItem("C3", Framework::SOC2, "Item 3", "D3");

    auto nistItems = tracker.getItemsByFramework(Framework::NIST);
    CHECK(nistItems.size() == 2);

    auto socItems = tracker.getItemsByFramework(Framework::SOC2);
    CHECK(socItems.size() == 1);
}

TEST_CASE("RemediationTracker - assign owner") {
    RemediationTracker tracker;

    auto result = tracker.createItem("C1", Framework::NIST, "Item 1", "D1");
    REQUIRE(result.isOk());

    auto assignResult = tracker.assignOwner(result.value().id, "security-team");
    REQUIRE(assignResult.isOk());

    auto item = tracker.getItem(result.value().id);
    CHECK(item->owner == "security-team");
}

TEST_CASE("RemediationTracker - get items by owner") {
    RemediationTracker tracker;

    auto r1 = tracker.createItem("C1", Framework::NIST, "Item 1", "D1");
    auto r2 = tracker.createItem("C2", Framework::NIST, "Item 2", "D2");
    REQUIRE(r1.isOk());
    REQUIRE(r2.isOk());

    (void)tracker.assignOwner(r1.value().id, "alice");
    (void)tracker.assignOwner(r2.value().id, "bob");

    auto aliceItems = tracker.getItemsByOwner("alice");
    CHECK(aliceItems.size() == 1);
    CHECK(aliceItems[0].title == "Item 1");

    auto bobItems = tracker.getItemsByOwner("bob");
    CHECK(bobItems.size() == 1);
}

TEST_CASE("RemediationTracker - set due date") {
    RemediationTracker tracker;

    auto result = tracker.createItem("C1", Framework::NIST, "Item 1", "D1");
    REQUIRE(result.isOk());

    auto dateResult = tracker.setDueDate(result.value().id, "2025-03-01");
    REQUIRE(dateResult.isOk());

    auto item = tracker.getItem(result.value().id);
    CHECK(item->dueDate == "2025-03-01");
}

TEST_CASE("RemediationTracker - status transitions") {
    RemediationTracker tracker;

    auto result = tracker.createItem("C1", Framework::NIST, "Item 1", "D1");
    REQUIRE(result.isOk());
    auto id = result.value().id;

    // Open -> InProgress
    (void)tracker.updateStatus(id, RemediationStatus::InProgress);
    CHECK(tracker.getItem(id)->status == RemediationStatus::InProgress);

    // InProgress -> Resolved
    (void)tracker.updateStatus(id, RemediationStatus::Resolved);
    CHECK(tracker.getItem(id)->status == RemediationStatus::Resolved);

    // Check status history
    auto item = tracker.getItem(id);
    CHECK(item->statusHistory.size() == 3); // Open, InProgress, Resolved
    CHECK(item->statusHistory[0].first == RemediationStatus::Open);
    CHECK(item->statusHistory[1].first == RemediationStatus::InProgress);
    CHECK(item->statusHistory[2].first == RemediationStatus::Resolved);
}

TEST_CASE("RemediationTracker - add verification steps") {
    RemediationTracker tracker;

    auto result = tracker.createItem("C1", Framework::NIST, "Item 1", "D1");
    REQUIRE(result.isOk());
    auto id = result.value().id;

    (void)tracker.addVerificationStep(id, "Run vulnerability scan");
    (void)tracker.addVerificationStep(id, "Review access logs");
    (void)tracker.addVerificationStep(id, "Verify encryption enabled");

    auto item = tracker.getItem(id);
    CHECK(item->verificationSteps.size() == 3);
    CHECK(item->verificationSteps[0] == "Run vulnerability scan");
    CHECK(item->verificationSteps[1] == "Review access logs");
    CHECK(item->verificationSteps[2] == "Verify encryption enabled");
}

TEST_CASE("RemediationTracker - check overdue") {
    RemediationTracker tracker;

    auto r1 = tracker.createItem("C1", Framework::NIST, "Old Item", "D1");
    auto r2 = tracker.createItem("C2", Framework::NIST, "Future Item", "D2");
    REQUIRE(r1.isOk());
    REQUIRE(r2.isOk());

    (void)tracker.setDueDate(r1.value().id, "2024-01-01");
    (void)tracker.setDueDate(r2.value().id, "2026-12-31");

    auto overdue = tracker.checkOverdue("2025-06-15");
    CHECK(overdue.size() == 1);
    CHECK(overdue[0].title == "Old Item");
    CHECK(overdue[0].status == RemediationStatus::Overdue);

    // Verify the item is now marked overdue in store
    auto item = tracker.getItem(r1.value().id);
    CHECK(item->status == RemediationStatus::Overdue);
}

TEST_CASE("RemediationTracker - resolved items not marked overdue") {
    RemediationTracker tracker;

    auto result = tracker.createItem("C1", Framework::NIST, "Resolved Item", "D1");
    REQUIRE(result.isOk());

    (void)tracker.setDueDate(result.value().id, "2024-01-01");
    (void)tracker.updateStatus(result.value().id, RemediationStatus::Resolved);

    auto overdue = tracker.checkOverdue("2025-06-15");
    CHECK(overdue.empty());
}

TEST_CASE("RemediationTracker - remove item") {
    RemediationTracker tracker;

    auto result = tracker.createItem("C1", Framework::NIST, "Item 1", "D1");
    REQUIRE(result.isOk());
    CHECK(tracker.getItemCount() == 1);

    auto removeResult = tracker.removeItem(result.value().id);
    REQUIRE(removeResult.isOk());
    CHECK(tracker.getItemCount() == 0);
}

TEST_CASE("RemediationTracker - validation errors") {
    RemediationTracker tracker;

    SUBCASE("Empty control ID") {
        auto result = tracker.createItem("", Framework::NIST, "Title", "Desc");
        REQUIRE(result.isErr());
        CHECK(result.error().category() == ThreatOne::Core::ErrorCategory::Validation);
    }

    SUBCASE("Empty title") {
        auto result = tracker.createItem("C1", Framework::NIST, "", "Desc");
        REQUIRE(result.isErr());
        CHECK(result.error().category() == ThreatOne::Core::ErrorCategory::Validation);
    }

    SUBCASE("Assign empty owner") {
        auto r = tracker.createItem("C1", Framework::NIST, "T", "D");
        REQUIRE(r.isOk());
        auto assignResult = tracker.assignOwner(r.value().id, "");
        REQUIRE(assignResult.isErr());
    }

    SUBCASE("Set empty due date") {
        auto r = tracker.createItem("C1", Framework::NIST, "T", "D");
        REQUIRE(r.isOk());
        auto dateResult = tracker.setDueDate(r.value().id, "");
        REQUIRE(dateResult.isErr());
    }

    SUBCASE("Update nonexistent item") {
        auto result = tracker.updateStatus("nonexistent", RemediationStatus::Resolved);
        REQUIRE(result.isErr());
    }
}

TEST_CASE("RemediationTracker - clear all") {
    RemediationTracker tracker;

    (void)tracker.createItem("C1", Framework::NIST, "Item 1", "D1");
    (void)tracker.createItem("C2", Framework::SOC2, "Item 2", "D2");
    CHECK(tracker.getItemCount() == 2);

    tracker.clearAll();
    CHECK(tracker.getItemCount() == 0);
}
