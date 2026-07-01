// ThreatOne Database - Migration System Implementation
// Manages schema versioning with ordered up/down migrations.

#include <database/Migration.h>
#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace ThreatOne::Database {

MigrationManager::MigrationManager() = default;
MigrationManager::~MigrationManager() = default;

void MigrationManager::registerMigration(std::unique_ptr<IMigration> migration) {
    migrations_.push_back(std::move(migration));
    // Keep migrations sorted by version
    std::sort(migrations_.begin(), migrations_.end(),
        [](const auto& a, const auto& b) {
            return a->version() < b->version();
        });
}

Core::Result<int, Core::Error> MigrationManager::runPending(IConnection& conn) {
    auto ensureResult = ensureMigrationsTable(conn);
    if (ensureResult.isErr()) {
        return Core::Result<int, Core::Error>::err(ensureResult.error());
    }

    auto versionResult = getCurrentVersion(conn);
    if (versionResult.isErr()) {
        return Core::Result<int, Core::Error>::err(versionResult.error());
    }

    int currentVersion = versionResult.value();
    int applied = 0;

    for (const auto& migration : migrations_) {
        if (migration->version() > currentVersion) {
            auto txBegin = conn.beginTransaction();
            if (txBegin.isErr()) {
                return Core::Result<int, Core::Error>::err(txBegin.error());
            }

            auto upResult = migration->up(conn);
            if (upResult.isErr()) {
                [[maybe_unused]] auto _ = conn.rollback();
                return Core::Result<int, Core::Error>::err(
                    Core::Error("Migration " + std::to_string(migration->version()) +
                               " (" + migration->name() + ") failed: " + upResult.error().message(),
                               Core::ErrorCategory::Database));
            }

            auto recordResult = recordMigration(conn, *migration);
            if (recordResult.isErr()) {
                [[maybe_unused]] auto _ = conn.rollback();
                return Core::Result<int, Core::Error>::err(recordResult.error());
            }

            auto commitResult = conn.commit();
            if (commitResult.isErr()) {
                [[maybe_unused]] auto _ = conn.rollback();
                return Core::Result<int, Core::Error>::err(commitResult.error());
            }

            applied++;
        }
    }

    return Core::Result<int, Core::Error>::ok(applied);
}

Core::Result<int, Core::Error> MigrationManager::rollback(IConnection& conn, int steps) {
    auto ensureResult = ensureMigrationsTable(conn);
    if (ensureResult.isErr()) {
        return Core::Result<int, Core::Error>::err(ensureResult.error());
    }

    auto appliedResult = getAppliedMigrations(conn);
    if (appliedResult.isErr()) {
        return Core::Result<int, Core::Error>::err(appliedResult.error());
    }

    auto& applied = appliedResult.value();
    int rolled = 0;

    // Rollback from most recent to oldest
    for (int i = static_cast<int>(applied.size()) - 1; i >= 0 && rolled < steps; --i) {
        int version = applied[static_cast<std::size_t>(i)].version;

        // Find the migration object
        IMigration* migration = nullptr;
        for (const auto& m : migrations_) {
            if (m->version() == version) {
                migration = m.get();
                break;
            }
        }

        if (!migration) {
            return Core::Result<int, Core::Error>::err(
                Core::Error("Migration version " + std::to_string(version) + " not found in registry",
                           Core::ErrorCategory::Database));
        }

        auto txBegin = conn.beginTransaction();
        if (txBegin.isErr()) {
            return Core::Result<int, Core::Error>::err(txBegin.error());
        }

        auto downResult = migration->down(conn);
        if (downResult.isErr()) {
            [[maybe_unused]] auto _ = conn.rollback();
            return Core::Result<int, Core::Error>::err(
                Core::Error("Rollback of migration " + std::to_string(version) +
                           " failed: " + downResult.error().message(),
                           Core::ErrorCategory::Database));
        }

        auto removeResult = removeMigrationRecord(conn, version);
        if (removeResult.isErr()) {
            [[maybe_unused]] auto _ = conn.rollback();
            return Core::Result<int, Core::Error>::err(removeResult.error());
        }

        auto commitResult = conn.commit();
        if (commitResult.isErr()) {
            [[maybe_unused]] auto _ = conn.rollback();
            return Core::Result<int, Core::Error>::err(commitResult.error());
        }

        rolled++;
    }

    return Core::Result<int, Core::Error>::ok(rolled);
}

Core::Result<int, Core::Error> MigrationManager::rollbackAll(IConnection& conn) {
    auto appliedResult = getAppliedMigrations(conn);
    if (appliedResult.isErr()) {
        return Core::Result<int, Core::Error>::err(appliedResult.error());
    }
    return rollback(conn, static_cast<int>(appliedResult.value().size()));
}

Core::Result<void, Core::Error> MigrationManager::migrateTo(IConnection& conn, int targetVersion) {
    auto versionResult = getCurrentVersion(conn);
    if (versionResult.isErr()) {
        return Core::Result<void, Core::Error>::err(versionResult.error());
    }

    int currentVersion = versionResult.value();

    if (targetVersion > currentVersion) {
        // Run migrations up to target
        for (const auto& migration : migrations_) {
            if (migration->version() > currentVersion && migration->version() <= targetVersion) {
                auto txBegin = conn.beginTransaction();
                if (txBegin.isErr()) {
                    return Core::Result<void, Core::Error>::err(txBegin.error());
                }

                auto upResult = migration->up(conn);
                if (upResult.isErr()) {
                    [[maybe_unused]] auto _ = conn.rollback();
                    return Core::Result<void, Core::Error>::err(upResult.error());
                }

                auto recordResult = recordMigration(conn, *migration);
                if (recordResult.isErr()) {
                    [[maybe_unused]] auto _ = conn.rollback();
                    return Core::Result<void, Core::Error>::err(recordResult.error());
                }

                auto commitResult = conn.commit();
                if (commitResult.isErr()) {
                    [[maybe_unused]] auto _ = conn.rollback();
                    return Core::Result<void, Core::Error>::err(commitResult.error());
                }
            }
        }
    } else if (targetVersion < currentVersion) {
        // Rollback to target version
        int stepsBack = currentVersion - targetVersion;
        auto rollbackResult = rollback(conn, stepsBack);
        if (rollbackResult.isErr()) {
            return Core::Result<void, Core::Error>::err(rollbackResult.error());
        }
    }

    return Core::Result<void, Core::Error>::ok();
}

Core::Result<int, Core::Error> MigrationManager::getCurrentVersion(IConnection& conn) {
    auto ensureResult = ensureMigrationsTable(conn);
    if (ensureResult.isErr()) {
        return Core::Result<int, Core::Error>::err(ensureResult.error());
    }

    auto result = conn.query(
        "SELECT COALESCE(MAX(version), 0) as version FROM _migrations", {});
    if (result.isErr()) {
        return Core::Result<int, Core::Error>::err(result.error());
    }

    if (result.value().rows.empty()) {
        return Core::Result<int, Core::Error>::ok(0);
    }

    return Core::Result<int, Core::Error>::ok(result.value().rows[0].getInt("version"));
}

Core::Result<std::vector<MigrationRecord>, Core::Error> MigrationManager::getAppliedMigrations(IConnection& conn) {
    auto ensureResult = ensureMigrationsTable(conn);
    if (ensureResult.isErr()) {
        return Core::Result<std::vector<MigrationRecord>, Core::Error>::err(ensureResult.error());
    }

    auto result = conn.query(
        "SELECT version, name, applied_at FROM _migrations ORDER BY version ASC", {});
    if (result.isErr()) {
        return Core::Result<std::vector<MigrationRecord>, Core::Error>::err(result.error());
    }

    std::vector<MigrationRecord> records;
    records.reserve(result.value().rows.size());
    for (const auto& row : result.value().rows) {
        MigrationRecord record;
        record.version = row.getInt("version");
        record.name = row.get("name");
        record.appliedAt = row.get("applied_at");
        records.push_back(std::move(record));
    }

    return Core::Result<std::vector<MigrationRecord>, Core::Error>::ok(std::move(records));
}

std::vector<const IMigration*> MigrationManager::getPendingMigrations(IConnection& conn) {
    std::vector<const IMigration*> pending;

    auto versionResult = getCurrentVersion(conn);
    if (versionResult.isErr()) {
        return pending;
    }

    int currentVersion = versionResult.value();
    for (const auto& migration : migrations_) {
        if (migration->version() > currentVersion) {
            pending.push_back(migration.get());
        }
    }

    return pending;
}

Core::Result<void, Core::Error> MigrationManager::ensureMigrationsTable(IConnection& conn) {
    return conn.execute(
        "CREATE TABLE IF NOT EXISTS _migrations ("
        "  version INTEGER PRIMARY KEY,"
        "  name TEXT NOT NULL,"
        "  applied_at TEXT NOT NULL"
        ")"
    );
}

Core::Result<void, Core::Error> MigrationManager::recordMigration(IConnection& conn, const IMigration& migration) {
    // Get current timestamp in ISO 8601 format
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::put_time(std::gmtime(&time), "%Y-%m-%dT%H:%M:%SZ");
    std::string timestamp = oss.str();

    return conn.execute(
        "INSERT INTO _migrations (version, name, applied_at) VALUES (?, ?, ?)",
        {
            BoundParam::integer(migration.version()),
            BoundParam::text(migration.name()),
            BoundParam::text(timestamp)
        }
    );
}

Core::Result<void, Core::Error> MigrationManager::removeMigrationRecord(IConnection& conn, int version) {
    return conn.execute(
        "DELETE FROM _migrations WHERE version = ?",
        {BoundParam::integer(version)}
    );
}

} // namespace ThreatOne::Database
