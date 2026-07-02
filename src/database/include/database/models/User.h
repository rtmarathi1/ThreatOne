#pragma once

// ThreatOne Database Model - User
// Represents system users with authentication and role information.

#include <string>
#include <vector>
#include <database/Model.h>
#include <utility>

namespace ThreatOne::Database::Models {

class User : public Model<User> {
public:
    // Table metadata
    static constexpr const char* tableName() { return "users"; }

    static std::vector<FieldMeta> fields() {
        return {
            {"id", FieldType::Integer, false, true},
            {"username", FieldType::Text, false, false},
            {"email", FieldType::Text, false, false},
            {"password_hash", FieldType::Text, false, false},
            {"role", FieldType::Text, false, false},
            {"created_at", FieldType::Timestamp, false, false},
            {"last_login", FieldType::Timestamp, true, false}
        };
    }

    // Populate from database row
    void fromRow(const Row& row);

    // Serialize to bound parameters for insert/update
    [[nodiscard]] std::vector<std::pair<std::string, BoundParam>> toParams() const;

    // JSON serialization
    [[nodiscard]] nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& j);

    // Field accessors
    [[nodiscard]] const std::string& username() const { return username_; }
    void setUsername(const std::string& val) { username_ = val; }

    [[nodiscard]] const std::string& email() const { return email_; }
    void setEmail(const std::string& val) { email_ = val; }

    [[nodiscard]] const std::string& passwordHash() const { return passwordHash_; }
    void setPasswordHash(const std::string& val) { passwordHash_ = val; }

    [[nodiscard]] const std::string& role() const { return role_; }
    void setRole(const std::string& val) { role_ = val; }

    [[nodiscard]] const std::string& createdAt() const { return createdAt_; }
    void setCreatedAt(const std::string& val) { createdAt_ = val; }

    [[nodiscard]] const std::string& lastLogin() const { return lastLogin_; }
    void setLastLogin(const std::string& val) { lastLogin_ = val; }

private:
    std::string username_;
    std::string email_;
    std::string passwordHash_;
    std::string role_ = "user";
    std::string createdAt_;
    std::string lastLogin_;
};

} // namespace ThreatOne::Database::Models
