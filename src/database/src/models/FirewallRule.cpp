// ThreatOne Database Model - FirewallRule Implementation

#include <database/models/FirewallRule.h>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace ThreatOne::Database::Models {

void FirewallRule::fromRow(const Row& row) {
    if (row.hasColumn("id")) setId(row.getInt64("id"));
    if (row.hasColumn("name")) name_ = row.get("name");
    if (row.hasColumn("direction")) direction_ = row.get("direction");
    if (row.hasColumn("action")) action_ = row.get("action");
    if (row.hasColumn("protocol")) protocol_ = row.get("protocol");
    if (row.hasColumn("source")) source_ = row.get("source");
    if (row.hasColumn("destination")) destination_ = row.get("destination");
    if (row.hasColumn("port")) port_ = row.getInt("port");
    if (row.hasColumn("enabled")) enabled_ = row.getBool("enabled");
}

std::vector<std::pair<std::string, BoundParam>> FirewallRule::toParams() const {
    return {
        {"name", BoundParam::text(name_)},
        {"direction", BoundParam::text(direction_)},
        {"action", BoundParam::text(action_)},
        {"protocol", protocol_.empty() ? BoundParam::null() : BoundParam::text(protocol_)},
        {"source", source_.empty() ? BoundParam::null() : BoundParam::text(source_)},
        {"destination", destination_.empty() ? BoundParam::null() : BoundParam::text(destination_)},
        {"port", BoundParam::integer(port_)},
        {"enabled", BoundParam::integer(enabled_ ? 1 : 0)}
    };
}

nlohmann::json FirewallRule::toJson() const {
    return {
        {"id", id()},
        {"name", name_},
        {"direction", direction_},
        {"action", action_},
        {"protocol", protocol_},
        {"source", source_},
        {"destination", destination_},
        {"port", port_},
        {"enabled", enabled_}
    };
}

void FirewallRule::fromJson(const nlohmann::json& j) {
    if (j.contains("id")) setId(j["id"].get<int64_t>());
    if (j.contains("name")) name_ = j["name"].get<std::string>();
    if (j.contains("direction")) direction_ = j["direction"].get<std::string>();
    if (j.contains("action")) action_ = j["action"].get<std::string>();
    if (j.contains("protocol")) protocol_ = j["protocol"].get<std::string>();
    if (j.contains("source")) source_ = j["source"].get<std::string>();
    if (j.contains("destination")) destination_ = j["destination"].get<std::string>();
    if (j.contains("port")) port_ = j["port"].get<int>();
    if (j.contains("enabled")) enabled_ = j["enabled"].get<bool>();
}

} // namespace ThreatOne::Database::Models
