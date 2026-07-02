#pragma once

// ThreatOne Database Model - Setting
// Key-value configuration settings stored in the database.

#include <string>
#include <vector>
#include <database/Model.h>
#include <utility>

namespace ThreatOne::Database::Models {

class Setting : public Model<Setting> {
public:
    static constexpr const char* tableName() { return "settings"; }

    static std::vector<FieldMeta> fields() {
        return {
            {"id", FieldType::Integer, false, true},
            {"key", FieldType::Text, false, false},
            {"value", FieldType::Text, false, false},
            {"category", FieldType::Text, true, false},
            {"description", FieldType::Text, true, false}
        };
    }

    void fromRow(const Row& row);
    [[nodiscard]] std::vector<std::pair<std::string, BoundParam>> toParams() const;
    [[nodiscard]] nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& j);

    [[nodiscard]] const std::string& key() const { return key_; }
    void setKey(const std::string& val) { key_ = val; }

    [[nodiscard]] const std::string& value() const { return value_; }
    void setValue(const std::string& val) { value_ = val; }

    [[nodiscard]] const std::string& category() const { return category_; }
    void setCategory(const std::string& val) { category_ = val; }

    [[nodiscard]] const std::string& description() const { return description_; }
    void setDescription(const std::string& val) { description_ = val; }

private:
    std::string key_;
    std::string value_;
    std::string category_;
    std::string description_;
};

} // namespace ThreatOne::Database::Models
