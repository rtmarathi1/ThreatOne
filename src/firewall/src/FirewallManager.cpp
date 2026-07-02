#include "firewall/FirewallManager.h"

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

namespace ThreatOne::Firewall {

FirewallManager::FirewallManager()
    : packetFilter_(std::make_unique<PacketFilter>(ruleEngine_))
    , logger_(Core::Logger::instance().getModuleLogger("FirewallManager")) {
    logger_.info("FirewallManager initialized");
}

bool FirewallManager::addRule(const FirewallRule& rule) {
    FirewallRule ruleToAdd = rule;
    if (ruleToAdd.id.empty()) {
        ruleToAdd.id = std::to_string(nextRuleId_.fetch_add(1));
    }
    bool result = ruleEngine_.addRule(ruleToAdd);
    if (result) {
        logger_.info("Added rule: {} (id: {})", ruleToAdd.name, ruleToAdd.id);
    }
    return result;
}

bool FirewallManager::removeRule(const std::string& ruleId) {
    bool result = ruleEngine_.removeRule(ruleId);
    if (result) {
        logger_.info("Removed rule: {}", ruleId);
    }
    return result;
}

std::vector<FirewallRule> FirewallManager::getRules() {
    return ruleEngine_.getRules();
}

bool FirewallManager::enableRule(const std::string& ruleId) {
    return ruleEngine_.enableRule(ruleId);
}

bool FirewallManager::disableRule(const std::string& ruleId) {
    return ruleEngine_.disableRule(ruleId);
}

std::vector<ConnectionInfo> FirewallManager::getConnections() {
    connectionTracker_.refresh();
    return connectionTracker_.getConnections();
}

bool FirewallManager::blockIP(const std::string& ip) {
    FirewallRule rule;
    rule.id = std::to_string(nextRuleId_.fetch_add(1));
    rule.name = "Block " + ip;
    rule.sourceIP = ip;
    rule.action = Action::Block;
    rule.direction = Direction::Inbound;
    rule.protocol = Protocol::Any;
    rule.priority = 0; // Highest priority
    rule.enabled = true;
    return ruleEngine_.addRule(rule);
}

bool FirewallManager::allowIP(const std::string& ip) {
    FirewallRule rule;
    rule.id = std::to_string(nextRuleId_.fetch_add(1));
    rule.name = "Allow " + ip;
    rule.sourceIP = ip;
    rule.action = Action::Allow;
    rule.direction = Direction::Inbound;
    rule.protocol = Protocol::Any;
    rule.priority = 0; // Highest priority
    rule.enabled = true;
    return ruleEngine_.addRule(rule);
}

FilterResult FirewallManager::filterPacket(const PacketDescriptor& packet) {
    return packetFilter_->filterPacket(packet);
}

} // namespace ThreatOne::Firewall
