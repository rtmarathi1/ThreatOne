#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <utility>

namespace ThreatOne::Firewall {

enum class Direction {
    Inbound,
    Outbound
};

enum class Action {
    Allow,
    Block,
    Log
};

enum class Protocol {
    TCP,
    UDP,
    ICMP,
    Any
};

struct FirewallRule {
    std::string id;
    std::string name;
    Direction direction = Direction::Inbound;
    Action action = Action::Block;
    Protocol protocol = Protocol::TCP;
    std::string sourceIP;
    std::string destIP;
    uint16_t sourcePort = 0;
    uint16_t destPort = 0;
    bool enabled = true;

    // Extended fields
    int priority = 0;
    std::string applicationPath;
    std::pair<uint16_t, uint16_t> sourcePortRange{0, 0};
    std::pair<uint16_t, uint16_t> destPortRange{0, 0};
    int sourceCidrPrefix = 0;
    int destCidrPrefix = 0;
};

struct PacketDescriptor {
    std::string sourceIP;
    std::string destIP;
    uint16_t sourcePort = 0;
    uint16_t destPort = 0;
    Protocol protocol = Protocol::TCP;
    Direction direction = Direction::Inbound;
    std::string applicationPath;
    std::string payload;
};

struct ConnectionInfo {
    std::string localAddress;
    std::string remoteAddress;
    uint16_t localPort = 0;
    uint16_t remotePort = 0;
    Protocol protocol = Protocol::TCP;
    std::string state;
    uint64_t processId = 0;
};

struct FilterResult {
    Action action = Action::Block;
    std::string matchedRuleId;
    std::string logMessage;
};

class IFirewallManager {
public:
    virtual ~IFirewallManager() = default;

    virtual bool addRule(const FirewallRule& rule) = 0;
    virtual bool removeRule(const std::string& ruleId) = 0;
    virtual std::vector<FirewallRule> getRules() = 0;
    virtual bool enableRule(const std::string& ruleId) = 0;
    virtual bool disableRule(const std::string& ruleId) = 0;
    virtual std::vector<ConnectionInfo> getConnections() = 0;
    virtual bool blockIP(const std::string& ip) = 0;
    virtual bool allowIP(const std::string& ip) = 0;
    virtual FilterResult filterPacket(const PacketDescriptor& packet) = 0;
};

} // namespace ThreatOne::Firewall
