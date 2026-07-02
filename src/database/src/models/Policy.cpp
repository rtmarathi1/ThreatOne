// ThreatOne Database Model - Policy Implementation

#include <database/models/Policy.h>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace ThreatOne::Database::Models {

void Policy::fromRow(const Row& row) {
    if (row.hasColumn("id")) setId(row.getInt64("id"));
    if (row.hasColumn("name")) name_ = row.get("name");
    if (row.hasColumn("type")) type_ = row.get("type");
    if (row.hasColumn("rules_json")) rulesJson_ = row.get("rules_json");
    if (row.hasColumn("enabled")) enabled_ = row.getBool("enabled");
    if (row.hasColumn("priority")) priority_ = row.getInt("priority");
}

std::vector<std::pair<std::string, BoundParam>> Policy::toParams() const {
    return {
        {"name", BoundParam::text(name_)},
        {"type", BoundParam::text(type_)},
        {"rules_json", BoundParam::text(rulesJson_)},
        {"enabled", BoundParam::integer(enabled_ ? 1 : 0)},
        {"priority", BoundParam::integer(priority_)}
    };
}

nlohmann::json Policy::toJson() const {
    return {
        {"id", id()},
        {"name", name_},
        {"type", type_},
        {"rules_json", rulesJson_},
        {"enabled", enabled_},
        {"priority", priority_}
    };
}

void Policy::fromJson(const nlohmann::json& j) {
    if (j.contains("id")) setId(j["id"].get<int64_t>());
    if (j.contains("name")) name_ = j["name"].get<std::string>();
    if (j.contains("type")) type_ = j["type"].get<std::string>();
    if (j.contains("rules_json")) rulesJson_ = j["rules_json"].get<std::string>();
    if (j.contains("enabled")) enabled_ = j["enabled"].get<bool>();
    if (j.contains("priority")) priority_ = j["priority"].get<int>();
}

} // namespace ThreatOne::Database::Models
