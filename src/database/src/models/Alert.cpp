// ThreatOne Database Model - Alert Implementation

#include <database/models/Alert.h>

namespace ThreatOne::Database::Models {

void Alert::fromRow(const Row& row) {
    if (row.hasColumn("id")) setId(row.getInt64("id"));
    if (row.hasColumn("type")) type_ = row.get("type");
    if (row.hasColumn("severity")) severity_ = row.get("severity");
    if (row.hasColumn("source")) source_ = row.get("source");
    if (row.hasColumn("message")) message_ = row.get("message");
    if (row.hasColumn("acknowledged")) acknowledged_ = row.getBool("acknowledged");
    if (row.hasColumn("created_at")) createdAt_ = row.get("created_at");
}

std::vector<std::pair<std::string, BoundParam>> Alert::toParams() const {
    return {
        {"type", BoundParam::text(type_)},
        {"severity", BoundParam::text(severity_)},
        {"source", source_.empty() ? BoundParam::null() : BoundParam::text(source_)},
        {"message", BoundParam::text(message_)},
        {"acknowledged", BoundParam::integer(acknowledged_ ? 1 : 0)},
        {"created_at", BoundParam::text(createdAt_)}
    };
}

nlohmann::json Alert::toJson() const {
    return {
        {"id", id()},
        {"type", type_},
        {"severity", severity_},
        {"source", source_},
        {"message", message_},
        {"acknowledged", acknowledged_},
        {"created_at", createdAt_}
    };
}

void Alert::fromJson(const nlohmann::json& j) {
    if (j.contains("id")) setId(j["id"].get<int64_t>());
    if (j.contains("type")) type_ = j["type"].get<std::string>();
    if (j.contains("severity")) severity_ = j["severity"].get<std::string>();
    if (j.contains("source")) source_ = j["source"].get<std::string>();
    if (j.contains("message")) message_ = j["message"].get<std::string>();
    if (j.contains("acknowledged")) acknowledged_ = j["acknowledged"].get<bool>();
    if (j.contains("created_at")) createdAt_ = j["created_at"].get<std::string>();
}

} // namespace ThreatOne::Database::Models
