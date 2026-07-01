// ThreatOne Database Model - Setting Implementation

#include <database/models/Setting.h>

namespace ThreatOne::Database::Models {

void Setting::fromRow(const Row& row) {
    if (row.hasColumn("id")) setId(row.getInt64("id"));
    if (row.hasColumn("key")) key_ = row.get("key");
    if (row.hasColumn("value")) value_ = row.get("value");
    if (row.hasColumn("category")) category_ = row.get("category");
    if (row.hasColumn("description")) description_ = row.get("description");
}

std::vector<std::pair<std::string, BoundParam>> Setting::toParams() const {
    return {
        {"key", BoundParam::text(key_)},
        {"value", BoundParam::text(value_)},
        {"category", category_.empty() ? BoundParam::null() : BoundParam::text(category_)},
        {"description", description_.empty() ? BoundParam::null() : BoundParam::text(description_)}
    };
}

nlohmann::json Setting::toJson() const {
    return {
        {"id", id()},
        {"key", key_},
        {"value", value_},
        {"category", category_},
        {"description", description_}
    };
}

void Setting::fromJson(const nlohmann::json& j) {
    if (j.contains("id")) setId(j["id"].get<int64_t>());
    if (j.contains("key")) key_ = j["key"].get<std::string>();
    if (j.contains("value")) value_ = j["value"].get<std::string>();
    if (j.contains("category")) category_ = j["category"].get<std::string>();
    if (j.contains("description")) description_ = j["description"].get<std::string>();
}

} // namespace ThreatOne::Database::Models
