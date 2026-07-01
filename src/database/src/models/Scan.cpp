// ThreatOne Database Model - Scan Implementation

#include <database/models/Scan.h>

namespace ThreatOne::Database::Models {

void Scan::fromRow(const Row& row) {
    if (row.hasColumn("id")) setId(row.getInt64("id"));
    if (row.hasColumn("type")) type_ = row.get("type");
    if (row.hasColumn("status")) status_ = row.get("status");
    if (row.hasColumn("target")) target_ = row.get("target");
    if (row.hasColumn("started_at")) startedAt_ = row.get("started_at");
    if (row.hasColumn("completed_at")) completedAt_ = row.get("completed_at");
    if (row.hasColumn("findings_count")) findingsCount_ = row.getInt("findings_count");
}

std::vector<std::pair<std::string, BoundParam>> Scan::toParams() const {
    return {
        {"type", BoundParam::text(type_)},
        {"status", BoundParam::text(status_)},
        {"target", BoundParam::text(target_)},
        {"started_at", startedAt_.empty() ? BoundParam::null() : BoundParam::text(startedAt_)},
        {"completed_at", completedAt_.empty() ? BoundParam::null() : BoundParam::text(completedAt_)},
        {"findings_count", BoundParam::integer(findingsCount_)}
    };
}

nlohmann::json Scan::toJson() const {
    return {
        {"id", id()},
        {"type", type_},
        {"status", status_},
        {"target", target_},
        {"started_at", startedAt_},
        {"completed_at", completedAt_},
        {"findings_count", findingsCount_}
    };
}

void Scan::fromJson(const nlohmann::json& j) {
    if (j.contains("id")) setId(j["id"].get<int64_t>());
    if (j.contains("type")) type_ = j["type"].get<std::string>();
    if (j.contains("status")) status_ = j["status"].get<std::string>();
    if (j.contains("target")) target_ = j["target"].get<std::string>();
    if (j.contains("started_at")) startedAt_ = j["started_at"].get<std::string>();
    if (j.contains("completed_at")) completedAt_ = j["completed_at"].get<std::string>();
    if (j.contains("findings_count")) findingsCount_ = j["findings_count"].get<int>();
}

} // namespace ThreatOne::Database::Models
