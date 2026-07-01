#include "firewall/PacketFilter.h"

namespace ThreatOne::Firewall {

PacketFilter::PacketFilter(RuleEngine& ruleEngine)
    : ruleEngine_(ruleEngine)
    , logger_(Core::Logger::instance().getModuleLogger("PacketFilter")) {
    logger_.info("PacketFilter initialized");
}

FilterResult PacketFilter::filterPacket(const PacketDescriptor& packet) {
    FilterResult result;

    // Delegate full evaluation to RuleEngine which returns both action and matched rule ID
    auto evalResult = ruleEngine_.evaluatePacket(packet);
    result.action = evalResult.action;
    result.matchedRuleId = evalResult.matchedRuleId;

    if (!result.matchedRuleId.empty()) {
        result.logMessage = "Packet " + packet.sourceIP + ":" +
            std::to_string(packet.sourcePort) + " -> " +
            packet.destIP + ":" + std::to_string(packet.destPort) +
            " matched rule: " + result.matchedRuleId;
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
