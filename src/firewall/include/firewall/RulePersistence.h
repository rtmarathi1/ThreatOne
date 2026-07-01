#pragma once

#include "firewall/IFirewallManager.h"
#include "core/Logger.h"
#include "core/Error.h"
#include "database/ConnectionManager.h"

#include <vector>
#include <string>

namespace ThreatOne::Firewall {

/// RulePersistence provides database CRUD operations for firewall rules.
///
/// Design intent: This is a standalone library component that is NOT automatically
/// wired into FirewallManager. Rules added through the manager live in memory only.
/// Application-layer code is responsible for:
///   1. Obtaining a Database::IConnection (via ConnectionManager).
///   2. Calling loadRules() at startup to hydrate the RuleEngine.
///   3. Calling saveRule()/deleteRule()/updateRule() when the application wants
///      durable persistence of rule changes.
///
/// This separation keeps the firewall engine testable without a database dependency
/// and allows the application to choose its own persistence strategy (e.g., batched
/// writes, write-through, periodic sync).
class RulePersistence {
public:
    RulePersistence();
    ~RulePersistence() = default;

    // CRUD operations
    [[nodiscard]] Core::Result<std::vector<FirewallRule>, Core::Error> loadRules(
        Database::IConnection& conn);

    [[nodiscard]] Core::Result<void, Core::Error> saveRule(
        Database::IConnection& conn, const FirewallRule& rule);

    [[nodiscard]] Core::Result<void, Core::Error> deleteRule(
        Database::IConnection& conn, const std::string& id);

    [[nodiscard]] Core::Result<void, Core::Error> updateRule(
        Database::IConnection& conn, const FirewallRule& rule);

private:
    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Firewall
