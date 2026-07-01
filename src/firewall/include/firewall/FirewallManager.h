#pragma once

#include "firewall/IFirewallManager.h"
#include "core/Logger.h"

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

private:
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Firewall
