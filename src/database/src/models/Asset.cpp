// ThreatOne Database Model - Asset Implementation

#include <database/models/Asset.h>

namespace ThreatOne::Database::Models {

void Asset::fromRow(const Row& row) {
    if (row.hasColumn("id")) setId(row.getInt64("id"));
    if (row.hasColumn("name")) name_ = row.get("name");
    if (row.hasColumn("type")) type_ = row.get("type");
    if (row.hasColumn("ip_address")) ipAddress_ = row.get("ip_address");
    if (row.hasColumn("mac_address")) macAddress_ = row.get("mac_address");
    if (row.hasColumn("os")) os_ = row.get("os");
    if (row.hasColumn("status")) status_ = row.get("status");
    if (row.hasColumn("risk_score")) riskScore_ = row.getDouble("risk_score");
}

std::vector<std::pair<std::string, BoundParam>> Asset::toParams() const {
    return {
        {"name", BoundParam::text(name_)},
        {"type", BoundParam::text(type_)},
        {"ip_address", ipAddress_.empty() ? BoundParam::null() : BoundParam::text(ipAddress_)},
        {"mac_address", macAddress_.empty() ? BoundParam::null() : BoundParam::text(macAddress_)},
        {"os", os_.empty() ? BoundParam::null() : BoundParam::text(os_)},
        {"status", BoundParam::text(status_)},
        {"risk_score", BoundParam::real(riskScore_)}
    };
}

nlohmann::json Asset::toJson() const {
    return {
        {"id", id()},
        {"name", name_},
        {"type", type_},
        {"ip_address", ipAddress_},
        {"mac_address", macAddress_},
        {"os", os_},
        {"status", status_},
        {"risk_score", riskScore_}
    };
}

void Asset::fromJson(const nlohmann::json& j) {
    if (j.contains("id")) setId(j["id"].get<int64_t>());
    if (j.contains("name")) name_ = j["name"].get<std::string>();
    if (j.contains("type")) type_ = j["type"].get<std::string>();
    if (j.contains("ip_address")) ipAddress_ = j["ip_address"].get<std::string>();
    if (j.contains("mac_address")) macAddress_ = j["mac_address"].get<std::string>();
    if (j.contains("os")) os_ = j["os"].get<std::string>();
    if (j.contains("status")) status_ = j["status"].get<std::string>();
    if (j.contains("risk_score")) riskScore_ = j["risk_score"].get<double>();
}

} // namespace ThreatOne::Database::Models
