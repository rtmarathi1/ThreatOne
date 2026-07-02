// ThreatOne Database Model - License Implementation

#include <database/models/License.h>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace ThreatOne::Database::Models {

void License::fromRow(const Row& row) {
    if (row.hasColumn("id")) setId(row.getInt64("id"));
    if (row.hasColumn("type")) type_ = row.get("type");
    if (row.hasColumn("key")) key_ = row.get("key");
    if (row.hasColumn("status")) status_ = row.get("status");
    if (row.hasColumn("expires_at")) expiresAt_ = row.get("expires_at");
    if (row.hasColumn("max_endpoints")) maxEndpoints_ = row.getInt("max_endpoints");
}

std::vector<std::pair<std::string, BoundParam>> License::toParams() const {
    return {
        {"type", BoundParam::text(type_)},
        {"key", BoundParam::text(key_)},
        {"status", BoundParam::text(status_)},
        {"expires_at", expiresAt_.empty() ? BoundParam::null() : BoundParam::text(expiresAt_)},
        {"max_endpoints", BoundParam::integer(maxEndpoints_)}
    };
}

nlohmann::json License::toJson() const {
    return {
        {"id", id()},
        {"type", type_},
        {"key", key_},
        {"status", status_},
        {"expires_at", expiresAt_},
        {"max_endpoints", maxEndpoints_}
    };
}

void License::fromJson(const nlohmann::json& j) {
    if (j.contains("id")) setId(j["id"].get<int64_t>());
    if (j.contains("type")) type_ = j["type"].get<std::string>();
    if (j.contains("key")) key_ = j["key"].get<std::string>();
    if (j.contains("status")) status_ = j["status"].get<std::string>();
    if (j.contains("expires_at")) expiresAt_ = j["expires_at"].get<std::string>();
    if (j.contains("max_endpoints")) maxEndpoints_ = j["max_endpoints"].get<int>();
}

} // namespace ThreatOne::Database::Models
