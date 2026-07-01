#pragma once

// ThreatOne Database Model - Policy
// Represents security policies with rule sets defined as JSON.

#include <string>
#include <vector>
#include <database/Model.h>

namespace ThreatOne::Database::Models {

class Policy : public Model<Policy> {
public:
    static constexpr const char* tableName() { return "policies"; }

    static std::vector<FieldMeta> fields() {
        return {
            {"id", FieldType::Integer, false, true},
            {"name", FieldType::Text, false, false},
            {"type", FieldType::Text, false, false},
            {"rules_json", FieldType::Text, false, false},
            {"enabled", FieldType::Boolean, false, false},
            {"priority", FieldType::Integer, false, false}
        };
    }

    void fromRow(const Row& row);
    [[nodiscard]] std::vector<std::pair<std::string, BoundParam>> toParams() const;
    [[nodiscard]] nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& j);

    [[nodiscard]] const std::string& name() const { return name_; }
    void setName(const std::string& val) { name_ = val; }

    [[nodiscard]] const std::string& type() const { return type_; }
    void setType(const std::string& val) { type_ = val; }

    [[nodiscard]] const std::string& rulesJson() const { return rulesJson_; }
    void setRulesJson(const std::string& val) { rulesJson_ = val; }

    [[nodiscard]] bool enabled() const { return enabled_; }
    void setEnabled(bool val) { enabled_ = val; }

    [[nodiscard]] int priority() const { return priority_; }
    void setPriority(int val) { priority_ = val; }

private:
    std::string name_;
    std::string type_;
    std::string rulesJson_ = "{}";
    bool enabled_ = true;
    int priority_ = 0;
};

} // namespace ThreatOne::Database::Models
