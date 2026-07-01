// ThreatOne Database Model - Threat Implementation

#include <database/models/Threat.h>

namespace ThreatOne::Database::Models {

void Threat::fromRow(const Row& row) {
    if (row.hasColumn("id")) setId(row.getInt64("id"));
    if (row.hasColumn("name")) name_ = row.get("name");
    if (row.hasColumn("severity")) severity_ = row.get("severity");
    if (row.hasColumn("category")) category_ = row.get("category");
    if (row.hasColumn("source")) source_ = row.get("source");
    if (row.hasColumn("first_seen")) firstSeen_ = row.get("first_seen");
    if (row.hasColumn("last_seen")) lastSeen_ = row.get("last_seen");
    if (row.hasColumn("status")) status_ = row.get("status");
}

std::vector<std::pair<std::string, BoundParam>> Threat::toParams() const {
    return {
        {"name", BoundParam::text(name_)},
        {"severity", BoundParam::text(severity_)},
        {"category", BoundParam::text(category_)},
        {"source", source_.empty() ? BoundParam::null() : BoundParam::text(source_)},
        {"first_seen", BoundParam::text(firstSeen_)},
        {"last_seen", BoundParam::text(lastSeen_)},
        {"status", BoundParam::text(status_)}
    };
}

nlohmann::json Threat::toJson() const {
    return {
        {"id", id()},
        {"name", name_},
        {"severity", severity_},
        {"category", category_},
        {"source", source_},
        {"first_seen", firstSeen_},
        {"last_seen", lastSeen_},
        {"status", status_}
    };
}

void Threat::fromJson(const nlohmann::json& j) {
    if (j.contains("id")) setId(j["id"].get<int64_t>());
    if (j.contains("name")) name_ = j["name"].get<std::string>();
    if (j.contains("severity")) severity_ = j["severity"].get<std::string>();
    if (j.contains("category")) category_ = j["category"].get<std::string>();
    if (j.contains("source")) source_ = j["source"].get<std::string>();
    if (j.contains("first_seen")) firstSeen_ = j["first_seen"].get<std::string>();
    if (j.contains("last_seen")) lastSeen_ = j["last_seen"].get<std::string>();
    if (j.contains("status")) status_ = j["status"].get<std::string>();
}

} // namespace ThreatOne::Database::Models
