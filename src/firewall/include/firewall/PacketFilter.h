#pragma once

#include "firewall/IFirewallManager.h"
#include "firewall/RuleEngine.h"
#include "core/Logger.h"

#include <string>
#include <mutex>
#include <atomic>
#include <cstdint>

namespace ThreatOne::Firewall {

// Statistics for packet filtering
struct FilterStats {
    uint64_t packetsAllowed = 0;
    uint64_t packetsDenied = 0;
    uint64_t packetsLogged = 0;
    uint64_t totalPackets = 0;
};

class PacketFilter {
public:
    explicit PacketFilter(RuleEngine& ruleEngine);
    ~PacketFilter() = default;

    // Evaluate a packet against the rule engine
    FilterResult filterPacket(const PacketDescriptor& packet);

    // Statistics
    FilterStats getStats() const;
    void resetStats();

private:
    RuleEngine& ruleEngine_;
    mutable std::mutex mutex_;
    FilterStats stats_;
    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Firewall
