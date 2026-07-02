// ThreatOne Database Model - User Implementation

#include <database/models/User.h>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace ThreatOne::Database::Models {

void User::fromRow(const Row& row) {
    if (row.hasColumn("id")) setId(row.getInt64("id"));
    if (row.hasColumn("username")) username_ = row.get("username");
    if (row.hasColumn("email")) email_ = row.get("email");
    if (row.hasColumn("password_hash")) passwordHash_ = row.get("password_hash");
    if (row.hasColumn("role")) role_ = row.get("role");
    if (row.hasColumn("created_at")) createdAt_ = row.get("created_at");
    if (row.hasColumn("last_login")) lastLogin_ = row.get("last_login");
}

std::vector<std::pair<std::string, BoundParam>> User::toParams() const {
    return {
        {"username", BoundParam::text(username_)},
        {"email", BoundParam::text(email_)},
        {"password_hash", BoundParam::text(passwordHash_)},
        {"role", BoundParam::text(role_)},
        {"created_at", BoundParam::text(createdAt_)},
        {"last_login", lastLogin_.empty() ? BoundParam::null() : BoundParam::text(lastLogin_)}
    };
}

nlohmann::json User::toJson() const {
    return {
        {"id", id()},
        {"username", username_},
        {"email", email_},
        {"role", role_},
        {"created_at", createdAt_},
        {"last_login", lastLogin_}
    };
}

void User::fromJson(const nlohmann::json& j) {
    if (j.contains("id")) setId(j["id"].get<int64_t>());
    if (j.contains("username")) username_ = j["username"].get<std::string>();
    if (j.contains("email")) email_ = j["email"].get<std::string>();
    if (j.contains("password_hash")) passwordHash_ = j["password_hash"].get<std::string>();
    if (j.contains("role")) role_ = j["role"].get<std::string>();
    if (j.contains("created_at")) createdAt_ = j["created_at"].get<std::string>();
    if (j.contains("last_login")) lastLogin_ = j["last_login"].get<std::string>();
}

} // namespace ThreatOne::Database::Models
