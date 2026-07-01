#include "firewall/RuleEngine.h"

#include <algorithm>
#include <sstream>
#include <cstring>
#include <arpa/inet.h>

namespace ThreatOne::Firewall {

RuleEngine::RuleEngine()
    : logger_(Core::Logger::instance().getModuleLogger("RuleEngine")) {
    logger_.info("RuleEngine initialized");
}

bool RuleEngine::addRule(const FirewallRule& rule) {
    std::lock_guard<std::mutex> lock(mutex_);
    // Check for duplicate ID
    for (const auto& existing : rules_) {
        if (existing.id == rule.id) {
            logger_.warn("Rule with id {} already exists", rule.id);
            return false;
        }
    }
    rules_.push_back(rule);
    sortRules();
    logger_.info("Added rule: {} (priority {})", rule.name, rule.priority);
    return true;
}

bool RuleEngine::removeRule(const std::string& ruleId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = std::find_if(rules_.begin(), rules_.end(),
        [&ruleId](const FirewallRule& r) { return r.id == ruleId; });
    if (it == rules_.end()) {
        logger_.warn("Rule {} not found for removal", ruleId);
        return false;
    }
    rules_.erase(it);
    logger_.info("Removed rule: {}", ruleId);
    return true;
}

std::vector<FirewallRule> RuleEngine::getRules() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return rules_;
}

bool RuleEngine::enableRule(const std::string& ruleId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = std::find_if(rules_.begin(), rules_.end(),
        [&ruleId](const FirewallRule& r) { return r.id == ruleId; });
    if (it == rules_.end()) {
        return false;
    }
    it->enabled = true;
    logger_.info("Enabled rule: {}", ruleId);
    return true;
}

bool RuleEngine::disableRule(const std::string& ruleId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = std::find_if(rules_.begin(), rules_.end(),
        [&ruleId](const FirewallRule& r) { return r.id == ruleId; });
    if (it == rules_.end()) {
        return false;
    }
    it->enabled = false;
    logger_.info("Disabled rule: {}", ruleId);
    return true;
}

Action RuleEngine::evaluatePacket(const PacketDescriptor& packet) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& rule : rules_) {
        if (!rule.enabled) {
            continue;
        }
        if (matchesRule(rule, packet)) {
            logger_.debug("Packet matched rule: {} (action: {})",
                rule.name, static_cast<int>(rule.action));
            return rule.action;
        }
    }
    return defaultAction_;
}

void RuleEngine::setDefaultAction(Action action) {
    std::lock_guard<std::mutex> lock(mutex_);
    defaultAction_ = action;
}

Action RuleEngine::getDefaultAction() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return defaultAction_;
}

void RuleEngine::sortRules() {
    // Sort by priority (lower number = higher priority = evaluated first)
    std::sort(rules_.begin(), rules_.end(),
        [](const FirewallRule& a, const FirewallRule& b) {
            return a.priority < b.priority;
        });
}

bool RuleEngine::matchesRule(const FirewallRule& rule, const PacketDescriptor& packet) const {
    // Check direction
    if (rule.direction != packet.direction) {
        return false;
    }

    // Check protocol
    if (rule.protocol != Protocol::Any && rule.protocol != packet.protocol) {
        return false;
    }

    // Check source IP with CIDR
    if (!rule.sourceIP.empty()) {
        int prefix = rule.sourceCidrPrefix > 0 ? rule.sourceCidrPrefix : 32;
        if (!matchCIDR(packet.sourceIP, rule.sourceIP, prefix)) {
            return false;
        }
    }

    // Check destination IP with CIDR
    if (!rule.destIP.empty()) {
        int prefix = rule.destCidrPrefix > 0 ? rule.destCidrPrefix : 32;
        if (!matchCIDR(packet.destIP, rule.destIP, prefix)) {
            return false;
        }
    }

    // Check source port range
    if (rule.sourcePortRange.first != 0 || rule.sourcePortRange.second != 0) {
        if (!matchPortRange(packet.sourcePort, rule.sourcePortRange)) {
            return false;
        }
    } else if (rule.sourcePort != 0) {
        if (packet.sourcePort != rule.sourcePort) {
            return false;
        }
    }

    // Check destination port range
    if (rule.destPortRange.first != 0 || rule.destPortRange.second != 0) {
        if (!matchPortRange(packet.destPort, rule.destPortRange)) {
            return false;
        }
    } else if (rule.destPort != 0) {
        if (packet.destPort != rule.destPort) {
            return false;
        }
    }

    // Check application path
    if (!rule.applicationPath.empty()) {
        if (packet.applicationPath != rule.applicationPath) {
            return false;
        }
    }

    return true;
}

uint32_t RuleEngine::parseIPv4(const std::string& ip) {
    struct in_addr addr{};
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
        return 0;
    }
    return ntohl(addr.s_addr);
}

bool RuleEngine::matchCIDR(const std::string& ip, const std::string& cidr, int prefix) {
    if (prefix <= 0 || prefix > 32) {
        prefix = 32;
    }

    uint32_t ipAddr = parseIPv4(ip);
    uint32_t cidrAddr = parseIPv4(cidr);

    if (prefix == 32) {
        return ipAddr == cidrAddr;
    }

    uint32_t mask = 0xFFFFFFFF << (32 - prefix);
    return (ipAddr & mask) == (cidrAddr & mask);
}

bool RuleEngine::matchPortRange(uint16_t port, std::pair<uint16_t, uint16_t> range) {
    if (range.first == 0 && range.second == 0) {
        return true; // No range specified, matches all
    }
    return port >= range.first && port <= range.second;
}

} // namespace ThreatOne::Firewall
