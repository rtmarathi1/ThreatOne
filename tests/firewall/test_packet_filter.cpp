#include <doctest/doctest.h>
#include <firewall/PacketFilter.h>
#include <firewall/RuleEngine.h>

using namespace ThreatOne::Firewall;

TEST_CASE("PacketFilter - initial stats are zero") {
    RuleEngine engine;
    PacketFilter filter(engine);

    auto stats = filter.getStats();
    CHECK(stats.packetsAllowed == 0);
    CHECK(stats.packetsDenied == 0);
    CHECK(stats.packetsLogged == 0);
    CHECK(stats.totalPackets == 0);
}

TEST_CASE("PacketFilter - allow packet matching allow rule") {
    RuleEngine engine;
    engine.setDefaultAction(Action::Block);

    FirewallRule rule;
    rule.id = "allow_http";
    rule.name = "Allow HTTP";
    rule.action = Action::Allow;
    rule.protocol = Protocol::TCP;
    rule.destPort = 80;
    rule.priority = 5;
    engine.addRule(rule);

    PacketFilter filter(engine);

    PacketDescriptor packet;
    packet.sourceIP = "10.0.0.1";
    packet.destIP = "10.0.0.2";
    packet.sourcePort = 12345;
    packet.destPort = 80;
    packet.protocol = Protocol::TCP;
    packet.direction = Direction::Inbound;

    FilterResult result = filter.filterPacket(packet);
    CHECK(result.action == Action::Allow);

    auto stats = filter.getStats();
    CHECK(stats.packetsAllowed == 1);
    CHECK(stats.totalPackets == 1);
}

TEST_CASE("PacketFilter - deny packet when default action is Block") {
    RuleEngine engine;
    engine.setDefaultAction(Action::Block);

    PacketFilter filter(engine);

    PacketDescriptor packet;
    packet.sourceIP = "10.0.0.1";
    packet.destIP = "10.0.0.2";
    packet.sourcePort = 12345;
    packet.destPort = 9999;
    packet.protocol = Protocol::TCP;
    packet.direction = Direction::Inbound;

    FilterResult result = filter.filterPacket(packet);
    CHECK(result.action == Action::Block);

    auto stats = filter.getStats();
    CHECK(stats.packetsDenied == 1);
    CHECK(stats.totalPackets == 1);
}

TEST_CASE("PacketFilter - log action") {
    RuleEngine engine;
    engine.setDefaultAction(Action::Block);

    FirewallRule rule;
    rule.id = "log_rule";
    rule.name = "Log Traffic";
    rule.action = Action::Log;
    rule.protocol = Protocol::Any;
    rule.priority = 5;
    engine.addRule(rule);

    PacketFilter filter(engine);

    PacketDescriptor packet;
    packet.sourceIP = "10.0.0.1";
    packet.destIP = "10.0.0.2";
    packet.protocol = Protocol::TCP;
    packet.direction = Direction::Inbound;

    FilterResult result = filter.filterPacket(packet);
    CHECK(result.action == Action::Log);

    auto stats = filter.getStats();
    CHECK(stats.packetsLogged == 1);
    CHECK(stats.totalPackets == 1);
}

TEST_CASE("PacketFilter - statistics accumulate") {
    RuleEngine engine;
    engine.setDefaultAction(Action::Allow);

    PacketFilter filter(engine);

    PacketDescriptor packet;
    packet.sourceIP = "10.0.0.1";
    packet.destIP = "10.0.0.2";
    packet.protocol = Protocol::TCP;
    packet.direction = Direction::Inbound;

    for (int i = 0; i < 5; i++) {
        filter.filterPacket(packet);
    }

    auto stats = filter.getStats();
    CHECK(stats.packetsAllowed == 5);
    CHECK(stats.totalPackets == 5);
}

TEST_CASE("PacketFilter - resetStats clears counters") {
    RuleEngine engine;
    engine.setDefaultAction(Action::Allow);

    PacketFilter filter(engine);

    PacketDescriptor packet;
    packet.sourceIP = "10.0.0.1";
    packet.destIP = "10.0.0.2";
    packet.protocol = Protocol::TCP;
    packet.direction = Direction::Inbound;

    filter.filterPacket(packet);
    filter.resetStats();

    auto stats = filter.getStats();
    CHECK(stats.packetsAllowed == 0);
    CHECK(stats.packetsDenied == 0);
    CHECK(stats.packetsLogged == 0);
    CHECK(stats.totalPackets == 0);
}

TEST_CASE("PacketFilter - matched rule ID in result") {
    RuleEngine engine;
    engine.setDefaultAction(Action::Block);

    FirewallRule rule;
    rule.id = "my_rule_123";
    rule.name = "My Rule";
    rule.action = Action::Allow;
    rule.protocol = Protocol::TCP;
    rule.destPort = 443;
    rule.priority = 5;
    engine.addRule(rule);

    PacketFilter filter(engine);

    PacketDescriptor packet;
    packet.sourceIP = "10.0.0.1";
    packet.destIP = "10.0.0.2";
    packet.sourcePort = 12345;
    packet.destPort = 443;
    packet.protocol = Protocol::TCP;
    packet.direction = Direction::Inbound;

    FilterResult result = filter.filterPacket(packet);
    CHECK(result.action == Action::Allow);
    CHECK(result.matchedRuleId == "my_rule_123");
}
