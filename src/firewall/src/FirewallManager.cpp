#include "firewall/FirewallManager.h"

namespace ThreatOne::Firewall {

FirewallManager::FirewallManager()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("FirewallManager")) {
    logger_.info("FirewallManager initialized (stub)");
}

bool FirewallManager::addRule(const FirewallRule& rule) {
    logger_.info("addRule called: {}", rule.name);
    return true;
}

bool FirewallManager::removeRule(const std::string& ruleId) {
    logger_.info("removeRule called: {}", ruleId);
    return true;
}

std::vector<FirewallRule> FirewallManager::getRules() {
    logger_.info("getRules called");
    return {};
}

bool FirewallManager::enableRule(const std::string& ruleId) {
    logger_.info("enableRule called: {}", ruleId);
    return true;
}

bool FirewallManager::disableRule(const std::string& ruleId) {
    logger_.info("disableRule called: {}", ruleId);
    return true;
}

std::vector<ConnectionInfo> FirewallManager::getConnections() {
    logger_.info("getConnections called");
    return {};
}

bool FirewallManager::blockIP(const std::string& ip) {
    logger_.info("blockIP called: {}", ip);
    return true;
}

bool FirewallManager::allowIP(const std::string& ip) {
    logger_.info("allowIP called: {}", ip);
    return true;
}

} // namespace ThreatOne::Firewall
