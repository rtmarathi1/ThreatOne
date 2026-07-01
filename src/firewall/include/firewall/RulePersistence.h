#pragma once

#include "firewall/IFirewallManager.h"
#include "core/Logger.h"
#include "core/Error.h"
#include "database/ConnectionManager.h"

#include <vector>
#include <string>

namespace ThreatOne::Firewall {

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
