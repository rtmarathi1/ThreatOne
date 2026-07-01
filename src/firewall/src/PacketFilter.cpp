#include "firewall/PacketFilter.h"

namespace ThreatOne::Firewall {

PacketFilter::PacketFilter(RuleEngine& ruleEngine)
    : ruleEngine_(ruleEngine)
    , logger_(Core::Logger::instance().getModuleLogger("PacketFilter")) {
    logger_.info("PacketFilter initialized");
}

FilterResult PacketFilter::filterPacket(const PacketDescriptor& packet) {
    FilterResult result;
    result.action = ruleEngine_.evaluatePacket(packet);

    // Find matched rule for the result
    auto rules = ruleEngine_.getRules();
    for (const auto& rule : rules) {
        if (!rule.enabled) continue;

        // Check if this is the matching rule by re-evaluating
        // We test by checking if a single-rule evaluation would produce the same action
        bool sourceMatch = rule.sourceIP.empty() ||
            RuleEngine::matchCIDR(packet.sourceIP, rule.sourceIP,
                rule.sourceCidrPrefix > 0 ? rule.sourceCidrPrefix : 32);
        bool destMatch = rule.destIP.empty() ||
            RuleEngine::matchCIDR(packet.destIP, rule.destIP,
                rule.destCidrPrefix > 0 ? rule.destCidrPrefix : 32);
        bool protoMatch = rule.protocol == Protocol::Any || rule.protocol == packet.protocol;
        bool dirMatch = rule.direction == packet.direction;

        if (sourceMatch && destMatch && protoMatch && dirMatch) {
            result.matchedRuleId = rule.id;
            result.logMessage = "Packet " + packet.sourceIP + ":" +
                std::to_string(packet.sourcePort) + " -> " +
                packet.destIP + ":" + std::to_string(packet.destPort) +
                " matched rule: " + rule.name;
            break;
        }
    }

    // Update statistics
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stats_.totalPackets++;
        switch (result.action) {
            case Action::Allow:
                stats_.packetsAllowed++;
                break;
            case Action::Block:
                stats_.packetsDenied++;
                break;
            case Action::Log:
                stats_.packetsLogged++;
                break;
        }
    }

    if (result.action == Action::Block) {
        logger_.debug("Blocked packet: {} -> {}", packet.sourceIP, packet.destIP);
    } else if (result.action == Action::Log) {
        logger_.info("Logged packet: {} -> {}", packet.sourceIP, packet.destIP);
    }

    return result;
}

FilterStats PacketFilter::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void PacketFilter::resetStats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_ = FilterStats{};
}

} // namespace ThreatOne::Firewall
