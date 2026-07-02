#include "firewall/RulePersistence.h"
#include "database/models/FirewallRule.h"
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace ThreatOne::Firewall {

namespace {

std::string directionToString(Direction dir) {
    switch (dir) {
        case Direction::Inbound: return "inbound";
        case Direction::Outbound: return "outbound";
    }
    return "inbound";
}

Direction directionFromString(const std::string& str) {
    if (str == "outbound") return Direction::Outbound;
    return Direction::Inbound;
}

std::string actionToString(Action action) {
    switch (action) {
        case Action::Allow: return "allow";
        case Action::Block: return "deny";
        case Action::Log: return "log";
    }
    return "deny";
}

Action actionFromString(const std::string& str) {
    if (str == "allow") return Action::Allow;
    if (str == "log") return Action::Log;
    return Action::Block;
}

std::string protocolToString(Protocol proto) {
    switch (proto) {
        case Protocol::TCP: return "tcp";
        case Protocol::UDP: return "udp";
        case Protocol::ICMP: return "icmp";
        case Protocol::Any: return "any";
    }
    return "tcp";
}

Protocol protocolFromString(const std::string& str) {
    if (str == "udp") return Protocol::UDP;
    if (str == "icmp") return Protocol::ICMP;
    if (str == "any") return Protocol::Any;
    return Protocol::TCP;
}

FirewallRule fromDbModel(const Database::Models::FirewallRule& dbRule) {
    FirewallRule rule;
    rule.id = std::to_string(dbRule.id());
    rule.name = dbRule.name();
    rule.direction = directionFromString(dbRule.direction());
    rule.action = actionFromString(dbRule.action());
    rule.protocol = protocolFromString(dbRule.protocol());
    rule.sourceIP = dbRule.source();
    rule.destIP = dbRule.destination();
    rule.destPort = static_cast<uint16_t>(dbRule.port());
    rule.enabled = dbRule.enabled();
    return rule;
}

Database::Models::FirewallRule toDbModel(const FirewallRule& rule) {
    Database::Models::FirewallRule dbRule;
    if (!rule.id.empty()) {
        try {
            dbRule.setId(std::stoll(rule.id));
        } catch (...) {
            // Non-numeric ID, leave as 0
        }
    }
    dbRule.setName(rule.name);
    dbRule.setDirection(directionToString(rule.direction));
    dbRule.setAction(actionToString(rule.action));
    dbRule.setProtocol(protocolToString(rule.protocol));
    dbRule.setSource(rule.sourceIP);
    dbRule.setDestination(rule.destIP);
    dbRule.setPort(rule.destPort);
    dbRule.setEnabled(rule.enabled);
    return dbRule;
}

} // anonymous namespace

RulePersistence::RulePersistence()
    : logger_(Core::Logger::instance().getModuleLogger("RulePersistence")) {
    logger_.info("RulePersistence initialized");
}

Core::Result<std::vector<FirewallRule>, Core::Error> RulePersistence::loadRules(
    Database::IConnection& conn) {

    auto result = Database::Models::FirewallRule::findAll(conn);
    if (result.isErr()) {
        logger_.error("Failed to load rules: {}", result.error().message());
        return Core::Result<std::vector<FirewallRule>, Core::Error>::err(result.error());
    }

    std::vector<FirewallRule> rules;
    rules.reserve(result.value().size());
    for (const auto& dbRule : result.value()) {
        rules.push_back(fromDbModel(dbRule));
    }

    logger_.info("Loaded {} rules from database", rules.size());
    return Core::Result<std::vector<FirewallRule>, Core::Error>::ok(std::move(rules));
}

Core::Result<void, Core::Error> RulePersistence::saveRule(
    Database::IConnection& conn, const FirewallRule& rule) {

    auto dbRule = toDbModel(rule);
    auto result = Database::Models::FirewallRule::create(conn, dbRule);
    if (result.isErr()) {
        logger_.error("Failed to save rule {}: {}", rule.name, result.error().message());
        return Core::Result<void, Core::Error>::err(result.error());
    }
    logger_.info("Saved rule: {}", rule.name);
    return Core::Result<void, Core::Error>::ok();
}

Core::Result<void, Core::Error> RulePersistence::deleteRule(
    Database::IConnection& conn, const std::string& id) {

    int64_t numericId = 0;
    try {
        numericId = std::stoll(id);
    } catch (...) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("Invalid rule ID: " + id, Core::ErrorCategory::Validation));
    }

    auto result = Database::Models::FirewallRule::destroyById(conn, numericId);
    if (result.isErr()) {
        logger_.error("Failed to delete rule {}: {}", id, result.error().message());
        return Core::Result<void, Core::Error>::err(result.error());
    }
    logger_.info("Deleted rule: {}", id);
    return Core::Result<void, Core::Error>::ok();
}

Core::Result<void, Core::Error> RulePersistence::updateRule(
    Database::IConnection& conn, const FirewallRule& rule) {

    auto dbRule = toDbModel(rule);
    auto result = dbRule.update(conn);
    if (result.isErr()) {
        logger_.error("Failed to update rule {}: {}", rule.id, result.error().message());
        return Core::Result<void, Core::Error>::err(result.error());
    }
    logger_.info("Updated rule: {}", rule.name);
    return Core::Result<void, Core::Error>::ok();
}

} // namespace ThreatOne::Firewall
