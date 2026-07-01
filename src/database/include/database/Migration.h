#pragma once

// ThreatOne Database - Migration System
// Provides version-tracked schema migrations with up/down support.
// Migrations are registered and applied in order, tracking state
// in a dedicated _migrations table.

#include <string>
#include <memory>
#include <vector>
#include <functional>
#include <chrono>

#include <core/Error.h>
#include "ConnectionManager.h"

namespace ThreatOne::Database {

// Migration interface - all schema migrations implement this
class IMigration {
public:
    virtual ~IMigration() = default;

    // Version number (must be unique and sequential)
    [[nodiscard]] virtual int version() const = 0;

    // Human-readable migration name
    [[nodiscard]] virtual std::string name() const = 0;

    // Apply the migration (create tables, add columns, etc.)
    [[nodiscard]] virtual Core::Result<void, Core::Error> up(IConnection& conn) = 0;

    // Reverse the migration (drop tables, remove columns, etc.)
    [[nodiscard]] virtual Core::Result<void, Core::Error> down(IConnection& conn) = 0;
};

// Record of an applied migration
struct MigrationRecord {
    int version = 0;
    std::string name;
    std::string appliedAt; // ISO 8601 timestamp
};

// Migration manager - orchestrates migration execution
class MigrationManager {
public:
    MigrationManager();
    ~MigrationManager();

    // Register a migration
    void registerMigration(std::unique_ptr<IMigration> migration);

    // Template helper to register migrations
    template<typename T, typename... Args>
    void addMigration(Args&&... args) {
        registerMigration(std::make_unique<T>(std::forward<Args>(args)...));
    }

    // Run all pending migrations
    [[nodiscard]] Core::Result<int, Core::Error> runPending(IConnection& conn);

    // Rollback the last N migrations
    [[nodiscard]] Core::Result<int, Core::Error> rollback(IConnection& conn, int steps = 1);

    // Rollback all migrations
    [[nodiscard]] Core::Result<int, Core::Error> rollbackAll(IConnection& conn);

    // Migrate to a specific version
    [[nodiscard]] Core::Result<void, Core::Error> migrateTo(IConnection& conn, int targetVersion);

    // Get current schema version
    [[nodiscard]] Core::Result<int, Core::Error> getCurrentVersion(IConnection& conn);

    // Get list of applied migrations
    [[nodiscard]] Core::Result<std::vector<MigrationRecord>, Core::Error> getAppliedMigrations(IConnection& conn);

    // Get list of pending migrations
    [[nodiscard]] std::vector<const IMigration*> getPendingMigrations(IConnection& conn);

    // Get all registered migrations
    [[nodiscard]] const std::vector<std::unique_ptr<IMigration>>& migrations() const { return migrations_; }

private:
    // Ensure the migrations tracking table exists
    [[nodiscard]] Core::Result<void, Core::Error> ensureMigrationsTable(IConnection& conn);

    // Record that a migration was applied
    [[nodiscard]] Core::Result<void, Core::Error> recordMigration(IConnection& conn, const IMigration& migration);

    // Remove record of a migration
    [[nodiscard]] Core::Result<void, Core::Error> removeMigrationRecord(IConnection& conn, int version);

    std::vector<std::unique_ptr<IMigration>> migrations_;
};

} // namespace ThreatOne::Database
