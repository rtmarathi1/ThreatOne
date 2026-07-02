#pragma once

// ThreatOne Database Model - License
// Represents software license information for the platform.

#include <string>
#include <vector>
#include <database/Model.h>
#include <utility>

namespace ThreatOne::Database::Models {

class License : public Model<License> {
public:
    static constexpr const char* tableName() { return "licenses"; }

    static std::vector<FieldMeta> fields() {
        return {
            {"id", FieldType::Integer, false, true},
            {"type", FieldType::Text, false, false},
            {"key", FieldType::Text, false, false},
            {"status", FieldType::Text, false, false},
            {"expires_at", FieldType::Timestamp, true, false},
            {"max_endpoints", FieldType::Integer, false, false}
        };
    }

    void fromRow(const Row& row);
    [[nodiscard]] std::vector<std::pair<std::string, BoundParam>> toParams() const;
    [[nodiscard]] nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& j);

    [[nodiscard]] const std::string& type() const { return type_; }
    void setType(const std::string& val) { type_ = val; }

    [[nodiscard]] const std::string& key() const { return key_; }
    void setKey(const std::string& val) { key_ = val; }

    [[nodiscard]] const std::string& status() const { return status_; }
    void setStatus(const std::string& val) { status_ = val; }

    [[nodiscard]] const std::string& expiresAt() const { return expiresAt_; }
    void setExpiresAt(const std::string& val) { expiresAt_ = val; }

    [[nodiscard]] int maxEndpoints() const { return maxEndpoints_; }
    void setMaxEndpoints(int val) { maxEndpoints_ = val; }

private:
    std::string type_;
    std::string key_;
    std::string status_ = "active";
    std::string expiresAt_;
    int maxEndpoints_ = 100;
};

} // namespace ThreatOne::Database::Models
