#pragma once

#include "firewall/IFirewallManager.h"
#include "core/Logger.h"

#include <vector>
#include <string>
#include <mutex>
#include <cstdint>

namespace ThreatOne::Firewall {

class RuleEngine {
public:
    RuleEngine();
    ~RuleEngine() = default;

    // Rule management
    bool addRule(const FirewallRule& rule);
    bool removeRule(const std::string& ruleId);
    std::vector<FirewallRule> getRules() const;
    bool enableRule(const std::string& ruleId);
    bool disableRule(const std::string& ruleId);

    // Rule evaluation
    Action evaluatePacket(const PacketDescriptor& packet) const;

    // Configuration
    void setDefaultAction(Action action);
    Action getDefaultAction() const;

    // Utility - IP matching
    static bool matchCIDR(const std::string& ip, const std::string& cidr, int prefix);
    static bool matchPortRange(uint16_t port, std::pair<uint16_t, uint16_t> range);
    static uint32_t parseIPv4(const std::string& ip);

private:
    void sortRules();
    bool matchesRule(const FirewallRule& rule, const PacketDescriptor& packet) const;

    mutable std::mutex mutex_;
    std::vector<FirewallRule> rules_;
    Action defaultAction_ = Action::Block;
    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Firewall
