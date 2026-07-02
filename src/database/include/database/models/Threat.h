#pragma once

// ThreatOne Database Model - Threat
// Represents detected threats with severity and category classification.

#include <string>
#include <vector>
#include <database/Model.h>
#include <utility>

namespace ThreatOne::Database::Models {

class Threat : public Model<Threat> {
public:
    static constexpr const char* tableName() { return "threats"; }

    static std::vector<FieldMeta> fields() {
        return {
            {"id", FieldType::Integer, false, true},
            {"name", FieldType::Text, false, false},
            {"severity", FieldType::Text, false, false},
            {"category", FieldType::Text, false, false},
            {"source", FieldType::Text, true, false},
            {"first_seen", FieldType::Timestamp, false, false},
            {"last_seen", FieldType::Timestamp, false, false},
            {"status", FieldType::Text, false, false}
        };
    }

    void fromRow(const Row& row);
    [[nodiscard]] std::vector<std::pair<std::string, BoundParam>> toParams() const;
    [[nodiscard]] nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& j);

    [[nodiscard]] const std::string& name() const { return name_; }
    void setName(const std::string& val) { name_ = val; }

    [[nodiscard]] const std::string& severity() const { return severity_; }
    void setSeverity(const std::string& val) { severity_ = val; }

    [[nodiscard]] const std::string& category() const { return category_; }
    void setCategory(const std::string& val) { category_ = val; }

    [[nodiscard]] const std::string& source() const { return source_; }
    void setSource(const std::string& val) { source_ = val; }

    [[nodiscard]] const std::string& firstSeen() const { return firstSeen_; }
    void setFirstSeen(const std::string& val) { firstSeen_ = val; }

    [[nodiscard]] const std::string& lastSeen() const { return lastSeen_; }
    void setLastSeen(const std::string& val) { lastSeen_ = val; }

    [[nodiscard]] const std::string& status() const { return status_; }
    void setStatus(const std::string& val) { status_ = val; }

private:
    std::string name_;
    std::string severity_ = "medium";
    std::string category_;
    std::string source_;
    std::string firstSeen_;
    std::string lastSeen_;
    std::string status_ = "active";
};

} // namespace ThreatOne::Database::Models
