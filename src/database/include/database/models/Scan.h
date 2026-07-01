#pragma once

// ThreatOne Database Model - Scan
// Represents security scan operations (vulnerability, network, compliance, etc.)

#include <string>
#include <vector>
#include <database/Model.h>

namespace ThreatOne::Database::Models {

class Scan : public Model<Scan> {
public:
    static constexpr const char* tableName() { return "scans"; }

    static std::vector<FieldMeta> fields() {
        return {
            {"id", FieldType::Integer, false, true},
            {"type", FieldType::Text, false, false},
            {"status", FieldType::Text, false, false},
            {"target", FieldType::Text, false, false},
            {"started_at", FieldType::Timestamp, true, false},
            {"completed_at", FieldType::Timestamp, true, false},
            {"findings_count", FieldType::Integer, false, false}
        };
    }

    void fromRow(const Row& row);
    [[nodiscard]] std::vector<std::pair<std::string, BoundParam>> toParams() const;
    [[nodiscard]] nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& j);

    [[nodiscard]] const std::string& type() const { return type_; }
    void setType(const std::string& val) { type_ = val; }

    [[nodiscard]] const std::string& status() const { return status_; }
    void setStatus(const std::string& val) { status_ = val; }

    [[nodiscard]] const std::string& target() const { return target_; }
    void setTarget(const std::string& val) { target_ = val; }

    [[nodiscard]] const std::string& startedAt() const { return startedAt_; }
    void setStartedAt(const std::string& val) { startedAt_ = val; }

    [[nodiscard]] const std::string& completedAt() const { return completedAt_; }
    void setCompletedAt(const std::string& val) { completedAt_ = val; }

    [[nodiscard]] int findingsCount() const { return findingsCount_; }
    void setFindingsCount(int val) { findingsCount_ = val; }

private:
    std::string type_;
    std::string status_ = "pending";
    std::string target_;
    std::string startedAt_;
    std::string completedAt_;
    int findingsCount_ = 0;
};

} // namespace ThreatOne::Database::Models
