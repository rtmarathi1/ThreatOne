#include <doctest/doctest.h>
#include <firewall/RuleEngine.h>
#include <cstdint>

using namespace ThreatOne::Firewall;

TEST_CASE("RuleEngine - default action is Block") {
    RuleEngine engine;
    CHECK(engine.getDefaultAction() == Action::Block);
}

TEST_CASE("RuleEngine - set default action") {
    RuleEngine engine;
    engine.setDefaultAction(Action::Allow);
    CHECK(engine.getDefaultAction() == Action::Allow);
}

TEST_CASE("RuleEngine - add and retrieve rules") {
    RuleEngine engine;
    FirewallRule rule;
    rule.id = "rule1";
    rule.name = "Test Rule";
    rule.action = Action::Allow;
    rule.protocol = Protocol::TCP;
    rule.sourceIP = "192.168.1.0";
    rule.sourceCidrPrefix = 24;
    rule.destPort = 80;

    CHECK(engine.addRule(rule));
    auto rules = engine.getRules();
    REQUIRE(rules.size() == 1);
    CHECK(rules[0].id == "rule1");
    CHECK(rules[0].name == "Test Rule");
}

TEST_CASE("RuleEngine - remove rule") {
    RuleEngine engine;
    FirewallRule rule;
    rule.id = "rule1";
    rule.name = "Test";
    rule.action = Action::Allow;
    engine.addRule(rule);

    CHECK(engine.removeRule("rule1"));
    CHECK(engine.getRules().empty());
    CHECK_FALSE(engine.removeRule("nonexistent"));
}

TEST_CASE("RuleEngine - enable and disable rules") {
    RuleEngine engine;
    FirewallRule rule;
    rule.id = "rule1";
    rule.name = "Test";
    rule.action = Action::Allow;
    rule.enabled = true;
    engine.addRule(rule);

    CHECK(engine.disableRule("rule1"));
    auto rules = engine.getRules();
    CHECK_FALSE(rules[0].enabled);

    CHECK(engine.enableRule("rule1"));
    rules = engine.getRules();
    CHECK(rules[0].enabled);

    CHECK_FALSE(engine.enableRule("nonexistent"));
    CHECK_FALSE(engine.disableRule("nonexistent"));
}

TEST_CASE("RuleEngine - priority ordering (higher priority matches first)") {
    RuleEngine engine;

    // Lower priority number = evaluated first in this implementation
    FirewallRule blockRule;
    blockRule.id = "block";
    blockRule.name = "Block Rule";
    blockRule.action = Action::Block;
    blockRule.priority = 10;
    blockRule.protocol = Protocol::Any;
    blockRule.direction = Direction::Inbound;

    FirewallRule allowRule;
    allowRule.id = "allow";
    allowRule.name = "Allow Rule";
    allowRule.action = Action::Allow;
    allowRule.priority = 1;
    allowRule.protocol = Protocol::TCP;
    allowRule.destPort = 80;
    allowRule.direction = Direction::Inbound;

    engine.addRule(blockRule);
    engine.addRule(allowRule);

    PacketDescriptor packet;
    packet.sourceIP = "10.0.0.1";
    packet.destIP = "10.0.0.2";
    packet.sourcePort = 12345;
    packet.destPort = 80;
    packet.protocol = Protocol::TCP;
    packet.direction = Direction::Inbound;

    // Allow rule has lower priority number, evaluated first
    Action result = engine.evaluatePacket(packet).action;
    CHECK(result == Action::Allow);
}

TEST_CASE("RuleEngine - CIDR matching") {
    CHECK(RuleEngine::matchCIDR("192.168.1.5", "192.168.1.0", 24));
    CHECK(RuleEngine::matchCIDR("192.168.1.255", "192.168.1.0", 24));
    CHECK_FALSE(RuleEngine::matchCIDR("192.168.2.1", "192.168.1.0", 24));
    CHECK(RuleEngine::matchCIDR("10.0.0.1", "10.0.0.0", 8));
    CHECK(RuleEngine::matchCIDR("10.255.255.255", "10.0.0.0", 8));
    CHECK_FALSE(RuleEngine::matchCIDR("11.0.0.1", "10.0.0.0", 8));
}

TEST_CASE("RuleEngine - port range matching") {
    CHECK(RuleEngine::matchPortRange(80, {80, 90}));
    CHECK(RuleEngine::matchPortRange(85, {80, 90}));
    CHECK(RuleEngine::matchPortRange(90, {80, 90}));
    CHECK_FALSE(RuleEngine::matchPortRange(79, {80, 90}));
    CHECK_FALSE(RuleEngine::matchPortRange(91, {80, 90}));
}

TEST_CASE("RuleEngine - evaluatePacket with CIDR rule") {
    RuleEngine engine;
    engine.setDefaultAction(Action::Block);

    FirewallRule rule;
    rule.id = "cidr_allow";
    rule.name = "Allow LAN";
    rule.action = Action::Allow;
    rule.protocol = Protocol::TCP;
    rule.sourceIP = "192.168.1.0";
    rule.sourceCidrPrefix = 24;
    rule.priority = 5;
    engine.addRule(rule);

    PacketDescriptor lanPacket;
    lanPacket.sourceIP = "192.168.1.100";
    lanPacket.destIP = "10.0.0.1";
    lanPacket.sourcePort = 5000;
    lanPacket.destPort = 443;
    lanPacket.protocol = Protocol::TCP;
    lanPacket.direction = Direction::Inbound;

    CHECK(engine.evaluatePacket(lanPacket).action == Action::Allow);

    PacketDescriptor wanPacket;
    wanPacket.sourceIP = "8.8.8.8";
    wanPacket.destIP = "10.0.0.1";
    wanPacket.sourcePort = 5000;
    wanPacket.destPort = 443;
    wanPacket.protocol = Protocol::TCP;
    wanPacket.direction = Direction::Inbound;

    CHECK(engine.evaluatePacket(wanPacket).action == Action::Block);
}

TEST_CASE("RuleEngine - disabled rules are not evaluated") {
    RuleEngine engine;
    engine.setDefaultAction(Action::Block);

    FirewallRule rule;
    rule.id = "allow_all";
    rule.name = "Allow All";
    rule.action = Action::Allow;
    rule.protocol = Protocol::Any;
    rule.priority = 10;
    rule.enabled = true;
    engine.addRule(rule);

    PacketDescriptor packet;
    packet.sourceIP = "1.2.3.4";
    packet.destIP = "5.6.7.8";
    packet.protocol = Protocol::TCP;
    packet.direction = Direction::Inbound;

    CHECK(engine.evaluatePacket(packet).action == Action::Allow);

    engine.disableRule("allow_all");
    CHECK(engine.evaluatePacket(packet).action == Action::Block);
}

TEST_CASE("RuleEngine - default action when no rule matches") {
    RuleEngine engine;
    engine.setDefaultAction(Action::Allow);

    PacketDescriptor packet;
    packet.sourceIP = "1.2.3.4";
    packet.destIP = "5.6.7.8";
    packet.protocol = Protocol::TCP;
    packet.direction = Direction::Inbound;

    CHECK(engine.evaluatePacket(packet).action == Action::Allow);

    engine.setDefaultAction(Action::Block);
    CHECK(engine.evaluatePacket(packet).action == Action::Block);
}

TEST_CASE("RuleEngine - protocol matching") {
    RuleEngine engine;
    engine.setDefaultAction(Action::Block);

    FirewallRule rule;
    rule.id = "udp_allow";
    rule.name = "Allow UDP";
    rule.action = Action::Allow;
    rule.protocol = Protocol::UDP;
    rule.priority = 5;
    engine.addRule(rule);

    PacketDescriptor udpPacket;
    udpPacket.sourceIP = "1.2.3.4";
    udpPacket.destIP = "5.6.7.8";
    udpPacket.protocol = Protocol::UDP;
    udpPacket.direction = Direction::Inbound;

    PacketDescriptor tcpPacket;
    tcpPacket.sourceIP = "1.2.3.4";
    tcpPacket.destIP = "5.6.7.8";
    tcpPacket.protocol = Protocol::TCP;
    tcpPacket.direction = Direction::Inbound;

    CHECK(engine.evaluatePacket(udpPacket).action == Action::Allow);
    CHECK(engine.evaluatePacket(tcpPacket).action == Action::Block);
}

TEST_CASE("RuleEngine - application path matching") {
    RuleEngine engine;
    engine.setDefaultAction(Action::Block);

    FirewallRule rule;
    rule.id = "app_allow";
    rule.name = "Allow Browser";
    rule.action = Action::Allow;
    rule.protocol = Protocol::Any;
    rule.applicationPath = "/usr/bin/firefox";
    rule.priority = 5;
    rule.direction = Direction::Outbound;
    engine.addRule(rule);

    PacketDescriptor browserPacket;
    browserPacket.sourceIP = "1.2.3.4";
    browserPacket.destIP = "5.6.7.8";
    browserPacket.protocol = Protocol::TCP;
    browserPacket.direction = Direction::Outbound;
    browserPacket.applicationPath = "/usr/bin/firefox";

    PacketDescriptor otherPacket;
    otherPacket.sourceIP = "1.2.3.4";
    otherPacket.destIP = "5.6.7.8";
    otherPacket.protocol = Protocol::TCP;
    otherPacket.direction = Direction::Outbound;
    otherPacket.applicationPath = "/usr/bin/wget";

    CHECK(engine.evaluatePacket(browserPacket).action == Action::Allow);
    CHECK(engine.evaluatePacket(otherPacket).action == Action::Block);
}

TEST_CASE("RuleEngine - parseIPv4") {
    uint32_t ip = RuleEngine::parseIPv4("192.168.1.1");
    CHECK(ip == 0xC0A80101);

    ip = RuleEngine::parseIPv4("10.0.0.1");
    CHECK(ip == 0x0A000001);

    ip = RuleEngine::parseIPv4("255.255.255.255");
    CHECK(ip == 0xFFFFFFFF);

    ip = RuleEngine::parseIPv4("0.0.0.0");
    CHECK(ip == 0x00000000);
}
