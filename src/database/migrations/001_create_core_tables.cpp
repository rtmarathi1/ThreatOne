// ThreatOne Database Migration 001 - Create Core Tables Implementation

#include "001_create_core_tables.h"
#include <string>
#include <vector>

namespace ThreatOne::Database::Migrations {

Core::Result<void, Core::Error> CreateCoreTables::up(IConnection& conn) {
    // Users table
    {
        auto table = Schema::create("users");
        table.id();
        table.text("username").notNull().unique();
        table.text("email").notNull().unique();
        table.text("password_hash").notNull();
        table.text("role").notNull().defaultValue("'user'");
        table.timestamp("created_at").notNull().defaultValue("CURRENT_TIMESTAMP");
        table.timestamp("last_login");
        table.index("idx_users_username", {"username"});
        table.index("idx_users_email", {"email"});

        auto result = conn.execute(Schema::createIfNotExists(table));
        if (result.isErr()) return result;
        for (const auto& idx : table.toIndexSQL()) {
            auto idxResult = conn.execute(idx);
            if (idxResult.isErr()) return idxResult;
        }
    }

    // Assets table
    {
        auto table = Schema::create("assets");
        table.id();
        table.text("name").notNull();
        table.text("type").notNull();
        table.text("ip_address");
        table.text("mac_address");
        table.text("os");
        table.text("status").notNull().defaultValue("'active'");
        table.real("risk_score").notNull().defaultValue("0.0");
        table.index("idx_assets_name", {"name"});
        table.index("idx_assets_type", {"type"});
        table.index("idx_assets_status", {"status"});

        auto result = conn.execute(Schema::createIfNotExists(table));
        if (result.isErr()) return result;
        for (const auto& idx : table.toIndexSQL()) {
            auto idxResult = conn.execute(idx);
            if (idxResult.isErr()) return idxResult;
        }
    }

    // Threats table
    {
        auto table = Schema::create("threats");
        table.id();
        table.text("name").notNull();
        table.text("severity").notNull().defaultValue("'medium'");
        table.text("category").notNull();
        table.text("source");
        table.timestamp("first_seen").notNull().defaultValue("CURRENT_TIMESTAMP");
        table.timestamp("last_seen").notNull().defaultValue("CURRENT_TIMESTAMP");
        table.text("status").notNull().defaultValue("'active'");
        table.index("idx_threats_severity", {"severity"});
        table.index("idx_threats_category", {"category"});
        table.index("idx_threats_status", {"status"});

        auto result = conn.execute(Schema::createIfNotExists(table));
        if (result.isErr()) return result;
        for (const auto& idx : table.toIndexSQL()) {
            auto idxResult = conn.execute(idx);
            if (idxResult.isErr()) return idxResult;
        }
    }

    // Incidents table
    {
        auto table = Schema::create("incidents");
        table.id();
        table.text("title").notNull();
        table.text("severity").notNull().defaultValue("'medium'");
        table.text("status").notNull().defaultValue("'open'");
        table.text("assignee");
        table.timestamp("created_at").notNull().defaultValue("CURRENT_TIMESTAMP");
        table.timestamp("resolved_at");
        table.text("description");
        table.index("idx_incidents_severity", {"severity"});
        table.index("idx_incidents_status", {"status"});
        table.index("idx_incidents_assignee", {"assignee"});

        auto result = conn.execute(Schema::createIfNotExists(table));
        if (result.isErr()) return result;
        for (const auto& idx : table.toIndexSQL()) {
            auto idxResult = conn.execute(idx);
            if (idxResult.isErr()) return idxResult;
        }
    }

    // Alerts table
    {
        auto table = Schema::create("alerts");
        table.id();
        table.text("type").notNull();
        table.text("severity").notNull().defaultValue("'info'");
        table.text("source");
        table.text("message").notNull();
        table.integer("acknowledged").notNull().defaultValue("0");
        table.timestamp("created_at").notNull().defaultValue("CURRENT_TIMESTAMP");
        table.index("idx_alerts_type", {"type"});
        table.index("idx_alerts_severity", {"severity"});
        table.index("idx_alerts_acknowledged", {"acknowledged"});

        auto result = conn.execute(Schema::createIfNotExists(table));
        if (result.isErr()) return result;
        for (const auto& idx : table.toIndexSQL()) {
            auto idxResult = conn.execute(idx);
            if (idxResult.isErr()) return idxResult;
        }
    }

    // Scans table
    {
        auto table = Schema::create("scans");
        table.id();
        table.text("type").notNull();
        table.text("status").notNull().defaultValue("'pending'");
        table.text("target").notNull();
        table.timestamp("started_at");
        table.timestamp("completed_at");
        table.integer("findings_count").notNull().defaultValue("0");
        table.index("idx_scans_type", {"type"});
        table.index("idx_scans_status", {"status"});

        auto result = conn.execute(Schema::createIfNotExists(table));
        if (result.isErr()) return result;
        for (const auto& idx : table.toIndexSQL()) {
            auto idxResult = conn.execute(idx);
            if (idxResult.isErr()) return idxResult;
        }
    }

    // Settings table
    {
        auto table = Schema::create("settings");
        table.id();
        table.text("key").notNull().unique();
        table.text("value").notNull();
        table.text("category");
        table.text("description");
        table.uniqueIndex("idx_settings_key", {"key"});

        auto result = conn.execute(Schema::createIfNotExists(table));
        if (result.isErr()) return result;
        for (const auto& idx : table.toIndexSQL()) {
            auto idxResult = conn.execute(idx);
            if (idxResult.isErr()) return idxResult;
        }
    }

    // Licenses table
    {
        auto table = Schema::create("licenses");
        table.id();
        table.text("type").notNull();
        table.text("key").notNull().unique();
        table.text("status").notNull().defaultValue("'active'");
        table.timestamp("expires_at");
        table.integer("max_endpoints").notNull().defaultValue("100");
        table.index("idx_licenses_status", {"status"});

        auto result = conn.execute(Schema::createIfNotExists(table));
        if (result.isErr()) return result;
        for (const auto& idx : table.toIndexSQL()) {
            auto idxResult = conn.execute(idx);
            if (idxResult.isErr()) return idxResult;
        }
    }

    // Firewall Rules table
    {
        auto table = Schema::create("firewall_rules");
        table.id();
        table.text("name").notNull();
        table.text("direction").notNull().defaultValue("'inbound'");
        table.text("action").notNull().defaultValue("'deny'");
        table.text("protocol");
        table.text("source");
        table.text("destination");
        table.integer("port");
        table.integer("enabled").notNull().defaultValue("1");
        table.index("idx_firewall_rules_direction", {"direction"});
        table.index("idx_firewall_rules_enabled", {"enabled"});

        auto result = conn.execute(Schema::createIfNotExists(table));
        if (result.isErr()) return result;
        for (const auto& idx : table.toIndexSQL()) {
            auto idxResult = conn.execute(idx);
            if (idxResult.isErr()) return idxResult;
        }
    }

    // Policies table
    {
        auto table = Schema::create("policies");
        table.id();
        table.text("name").notNull();
        table.text("type").notNull();
        table.text("rules_json").notNull().defaultValue("'{}'");
        table.integer("enabled").notNull().defaultValue("1");
        table.integer("priority").notNull().defaultValue("0");
        table.index("idx_policies_type", {"type"});
        table.index("idx_policies_enabled", {"enabled"});
        table.index("idx_policies_priority", {"priority"});

        auto result = conn.execute(Schema::createIfNotExists(table));
        if (result.isErr()) return result;
        for (const auto& idx : table.toIndexSQL()) {
            auto idxResult = conn.execute(idx);
            if (idxResult.isErr()) return idxResult;
        }
    }

    // Vulnerabilities table
    {
        auto table = Schema::create("vulnerabilities");
        table.id();
        table.text("cve_id");
        table.text("title").notNull();
        table.text("severity").notNull().defaultValue("'medium'");
        table.real("cvss_score").notNull().defaultValue("0.0");
        table.integer("affected_asset");
        table.text("status").notNull().defaultValue("'open'");
        table.timestamp("discovered_at").notNull().defaultValue("CURRENT_TIMESTAMP");
        table.foreignKey("affected_asset", "assets", "id", "SET NULL", "CASCADE");
        table.index("idx_vulnerabilities_severity", {"severity"});
        table.index("idx_vulnerabilities_status", {"status"});
        table.index("idx_vulnerabilities_cve", {"cve_id"});

        auto result = conn.execute(Schema::createIfNotExists(table));
        if (result.isErr()) return result;
        for (const auto& idx : table.toIndexSQL()) {
            auto idxResult = conn.execute(idx);
            if (idxResult.isErr()) return idxResult;
        }
    }

    return Core::Result<void, Core::Error>::ok();
}

Core::Result<void, Core::Error> CreateCoreTables::down(IConnection& conn) {
    // Drop tables in reverse order (respecting foreign key dependencies)
    const std::vector<std::string> tables = {
        "vulnerabilities",
        "policies",
        "firewall_rules",
        "licenses",
        "settings",
        "scans",
        "alerts",
        "incidents",
        "threats",
        "assets",
        "users"
    };

    for (const auto& table : tables) {
        auto result = conn.execute(Schema::dropIfExists(table));
        if (result.isErr()) return result;
    }

    return Core::Result<void, Core::Error>::ok();
}

} // namespace ThreatOne::Database::Migrations
