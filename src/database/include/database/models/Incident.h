#pragma once

// ThreatOne Database Model - Incident
// Represents security incidents requiring investigation and response.

#include <string>
#include <vector>
#include <database/Model.h>

namespace ThreatOne::Database::Models {

class Incident : public Model<Incident> {
public:
    static constexpr const char* tableName() { return "incidents"; }

    static std::vector<FieldMeta> fields() {
        return {
            {"id", FieldType::Integer, false, true},
            {"title", FieldType::Text, false, false},
            {"severity", FieldType::Text, false, false},
            {"status", FieldType::Text, false, false},
            {"assignee", FieldType::Text, true, false},
            {"created_at", FieldType::Timestamp, false, false},
            {"resolved_at", FieldType::Timestamp, true, false},
            {"description", FieldType::Text, true, false}
        };
    }

    void fromRow(const Row& row);
    [[nodiscard]] std::vector<std::pair<std::string, BoundParam>> toParams() const;
    [[nodiscard]] nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& j);

    [[nodiscard]] const std::string& title() const { return title_; }
    void setTitle(const std::string& val) { title_ = val; }

    [[nodiscard]] const std::string& severity() const { return severity_; }
    void setSeverity(const std::string& val) { severity_ = val; }

    [[nodiscard]] const std::string& status() const { return status_; }
    void setStatus(const std::string& val) { status_ = val; }

    [[nodiscard]] const std::string& assignee() const { return assignee_; }
    void setAssignee(const std::string& val) { assignee_ = val; }

    [[nodiscard]] const std::string& createdAt() const { return createdAt_; }
    void setCreatedAt(const std::string& val) { createdAt_ = val; }

    [[nodiscard]] const std::string& resolvedAt() const { return resolvedAt_; }
    void setResolvedAt(const std::string& val) { resolvedAt_ = val; }

    [[nodiscard]] const std::string& description() const { return description_; }
    void setDescription(const std::string& val) { description_ = val; }

private:
    std::string title_;
    std::string severity_ = "medium";
    std::string status_ = "open";
    std::string assignee_;
    std::string createdAt_;
    std::string resolvedAt_;
    std::string description_;
};

} // namespace ThreatOne::Database::Models
