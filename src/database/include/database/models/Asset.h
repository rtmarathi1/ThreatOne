#pragma once

// ThreatOne Database Model - Asset
// Represents network assets (devices, servers, endpoints) monitored by the platform.

#include <string>
#include <vector>
#include <database/Model.h>

namespace ThreatOne::Database::Models {

class Asset : public Model<Asset> {
public:
    static constexpr const char* tableName() { return "assets"; }

    static std::vector<FieldMeta> fields() {
        return {
            {"id", FieldType::Integer, false, true},
            {"name", FieldType::Text, false, false},
            {"type", FieldType::Text, false, false},
            {"ip_address", FieldType::Text, true, false},
            {"mac_address", FieldType::Text, true, false},
            {"os", FieldType::Text, true, false},
            {"status", FieldType::Text, false, false},
            {"risk_score", FieldType::Real, false, false}
        };
    }

    void fromRow(const Row& row);
    [[nodiscard]] std::vector<std::pair<std::string, BoundParam>> toParams() const;
    [[nodiscard]] nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& j);

    // Field accessors
    [[nodiscard]] const std::string& name() const { return name_; }
    void setName(const std::string& val) { name_ = val; }

    [[nodiscard]] const std::string& type() const { return type_; }
    void setType(const std::string& val) { type_ = val; }

    [[nodiscard]] const std::string& ipAddress() const { return ipAddress_; }
    void setIpAddress(const std::string& val) { ipAddress_ = val; }

    [[nodiscard]] const std::string& macAddress() const { return macAddress_; }
    void setMacAddress(const std::string& val) { macAddress_ = val; }

    [[nodiscard]] const std::string& os() const { return os_; }
    void setOs(const std::string& val) { os_ = val; }

    [[nodiscard]] const std::string& status() const { return status_; }
    void setStatus(const std::string& val) { status_ = val; }

    [[nodiscard]] double riskScore() const { return riskScore_; }
    void setRiskScore(double val) { riskScore_ = val; }

private:
    std::string name_;
    std::string type_;
    std::string ipAddress_;
    std::string macAddress_;
    std::string os_;
    std::string status_ = "active";
    double riskScore_ = 0.0;
};

} // namespace ThreatOne::Database::Models
