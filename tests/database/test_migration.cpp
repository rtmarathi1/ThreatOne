#include <doctest/doctest.h>
#include <database/Migration.h>
#include <memory>
#include <string>
#include <vector>
#include <utility>

using namespace ThreatOne::Database;
using namespace ThreatOne::Core;

// Mock migration implementations for testing
class MockMigration : public IMigration {
public:
    MockMigration(int ver, std::string name)
        : version_(ver), name_(std::move(name)) {}

    [[nodiscard]] int version() const override { return version_; }
    [[nodiscard]] std::string name() const override { return name_; }

    [[nodiscard]] Result<void, Error> up(IConnection& /*conn*/) override {
        upCalled = true;
        return Result<void, Error>::ok();
    }

    [[nodiscard]] Result<void, Error> down(IConnection& /*conn*/) override {
        downCalled = true;
        return Result<void, Error>::ok();
    }

    bool upCalled = false;
    bool downCalled = false;

private:
    int version_;
    std::string name_;
};

TEST_CASE("MigrationManager registration - single migration") {
    MigrationManager manager;

    manager.registerMigration(std::make_unique<MockMigration>(1, "create_users"));
    CHECK(manager.migrations().size() == 1);
    CHECK(manager.migrations()[0]->version() == 1);
    CHECK(manager.migrations()[0]->name() == "create_users");
}

TEST_CASE("MigrationManager registration - multiple migrations") {
    MigrationManager manager;

    manager.registerMigration(std::make_unique<MockMigration>(1, "create_users"));
    manager.registerMigration(std::make_unique<MockMigration>(2, "add_email"));
    manager.registerMigration(std::make_unique<MockMigration>(3, "create_roles"));

    CHECK(manager.migrations().size() == 3);
}

TEST_CASE("MigrationManager registration - sorted by version") {
    MigrationManager manager;

    // Register out of order
    manager.registerMigration(std::make_unique<MockMigration>(3, "third"));
    manager.registerMigration(std::make_unique<MockMigration>(1, "first"));
    manager.registerMigration(std::make_unique<MockMigration>(2, "second"));

    REQUIRE(manager.migrations().size() == 3);
    CHECK(manager.migrations()[0]->version() == 1);
    CHECK(manager.migrations()[0]->name() == "first");
    CHECK(manager.migrations()[1]->version() == 2);
    CHECK(manager.migrations()[1]->name() == "second");
    CHECK(manager.migrations()[2]->version() == 3);
    CHECK(manager.migrations()[2]->name() == "third");
}

TEST_CASE("MigrationManager addMigration template") {
    MigrationManager manager;

    manager.addMigration<MockMigration>(1, "template_migration");
    REQUIRE(manager.migrations().size() == 1);
    CHECK(manager.migrations()[0]->version() == 1);
    CHECK(manager.migrations()[0]->name() == "template_migration");
}

TEST_CASE("IMigration interface") {
    MockMigration migration(5, "test_migration");

    SUBCASE("Version and name accessors") {
        CHECK(migration.version() == 5);
        CHECK(migration.name() == "test_migration");
    }

    SUBCASE("Up and down are initially not called") {
        CHECK_FALSE(migration.upCalled);
        CHECK_FALSE(migration.downCalled);
    }
}

TEST_CASE("MigrationRecord structure") {
    MigrationRecord record;
    record.version = 1;
    record.name = "create_tables";
    record.appliedAt = "2024-01-15T10:30:00Z";

    CHECK(record.version == 1);
    CHECK(record.name == "create_tables");
    CHECK(record.appliedAt == "2024-01-15T10:30:00Z");
}

TEST_CASE("Migration version ordering integrity") {
    MigrationManager manager;

    // Register several migrations in random order
    manager.registerMigration(std::make_unique<MockMigration>(10, "tenth"));
    manager.registerMigration(std::make_unique<MockMigration>(1, "first"));
    manager.registerMigration(std::make_unique<MockMigration>(5, "fifth"));
    manager.registerMigration(std::make_unique<MockMigration>(7, "seventh"));
    manager.registerMigration(std::make_unique<MockMigration>(3, "third"));

    REQUIRE(manager.migrations().size() == 5);

    // Verify strict ordering
    for (size_t i = 1; i < manager.migrations().size(); ++i) {
        CHECK(manager.migrations()[i]->version() > manager.migrations()[i - 1]->version());
    }
}
