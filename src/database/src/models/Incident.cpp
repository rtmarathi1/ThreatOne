// ThreatOne Database Model - Incident Implementation

#include <database/models/Incident.h>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace ThreatOne::Database::Models {

void Incident::fromRow(const Row& row) {
    if (row.hasColumn("id")) setId(row.getInt64("id"));
    if (row.hasColumn("title")) title_ = row.get("title");
    if (row.hasColumn("severity")) severity_ = row.get("severity");
    if (row.hasColumn("status")) status_ = row.get("status");
    if (row.hasColumn("assignee")) assignee_ = row.get("assignee");
    if (row.hasColumn("created_at")) createdAt_ = row.get("created_at");
    if (row.hasColumn("resolved_at")) resolvedAt_ = row.get("resolved_at");
    if (row.hasColumn("description")) description_ = row.get("description");
}

std::vector<std::pair<std::string, BoundParam>> Incident::toParams() const {
    return {
        {"title", BoundParam::text(title_)},
        {"severity", BoundParam::text(severity_)},
        {"status", BoundParam::text(status_)},
        {"assignee", assignee_.empty() ? BoundParam::null() : BoundParam::text(assignee_)},
        {"created_at", BoundParam::text(createdAt_)},
        {"resolved_at", resolvedAt_.empty() ? BoundParam::null() : BoundParam::text(resolvedAt_)},
        {"description", description_.empty() ? BoundParam::null() : BoundParam::text(description_)}
    };
}

nlohmann::json Incident::toJson() const {
    return {
        {"id", id()},
        {"title", title_},
        {"severity", severity_},
        {"status", status_},
        {"assignee", assignee_},
        {"created_at", createdAt_},
        {"resolved_at", resolvedAt_},
        {"description", description_}
    };
}

void Incident::fromJson(const nlohmann::json& j) {
    if (j.contains("id")) setId(j["id"].get<int64_t>());
    if (j.contains("title")) title_ = j["title"].get<std::string>();
    if (j.contains("severity")) severity_ = j["severity"].get<std::string>();
    if (j.contains("status")) status_ = j["status"].get<std::string>();
    if (j.contains("assignee")) assignee_ = j["assignee"].get<std::string>();
    if (j.contains("created_at")) createdAt_ = j["created_at"].get<std::string>();
    if (j.contains("resolved_at")) resolvedAt_ = j["resolved_at"].get<std::string>();
    if (j.contains("description")) description_ = j["description"].get<std::string>();
}

} // namespace ThreatOne::Database::Models
