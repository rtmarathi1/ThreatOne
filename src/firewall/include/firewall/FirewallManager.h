#pragma once

#include "firewall/IFirewallManager.h"
#include "firewall/RuleEngine.h"
#include "firewall/ConnectionTracker.h"
#include "firewall/PacketFilter.h"
#include "core/Logger.h"

#include <memory>
#include <atomic>
#include <string>
#include <vector>

namespace ThreatOne::Firewall {

class FirewallManager : public IFirewallManager {
public:
    FirewallManager();
    ~FirewallManager() override = default;

    bool addRule(const FirewallRule& rule) override;
    bool removeRule(const std::string& ruleId) override;
    std::vector<FirewallRule> getRules() override;
    bool enableRule(const std::string& ruleId) override;
    bool disableRule(const std::string& ruleId) override;
    std::vector<ConnectionInfo> getConnections() override;
    bool blockIP(const std::string& ip) override;
    bool allowIP(const std::string& ip) override;
    FilterResult filterPacket(const PacketDescriptor& packet) override;

    // Access to sub-components
    RuleEngine& ruleEngine() { return ruleEngine_; }
    ConnectionTracker& connectionTracker() { return connectionTracker_; }
    PacketFilter& packetFilter() { return *packetFilter_; }

private:
    RuleEngine ruleEngine_;
    ConnectionTracker connectionTracker_;
    std::unique_ptr<PacketFilter> packetFilter_;
    Core::ModuleLogger logger_;
    std::atomic<int> nextRuleId_{1};
};

} // namespace ThreatOne::Firewall
