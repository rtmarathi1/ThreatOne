#pragma once

// ThreatOne Database Model - FirewallRule
// Represents firewall rules configured in the platform.

#include <string>
#include <vector>
#include <database/Model.h>
#include <utility>

namespace ThreatOne::Database::Models {

class FirewallRule : public Model<FirewallRule> {
public:
    static constexpr const char* tableName() { return "firewall_rules"; }

    static std::vector<FieldMeta> fields() {
        return {
            {"id", FieldType::Integer, false, true},
            {"name", FieldType::Text, false, false},
            {"direction", FieldType::Text, false, false},
            {"action", FieldType::Text, false, false},
            {"protocol", FieldType::Text, true, false},
            {"source", FieldType::Text, true, false},
            {"destination", FieldType::Text, true, false},
            {"port", FieldType::Integer, true, false},
            {"enabled", FieldType::Boolean, false, false}
        };
    }

    void fromRow(const Row& row);
    [[nodiscard]] std::vector<std::pair<std::string, BoundParam>> toParams() const;
    [[nodiscard]] nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& j);

    [[nodiscard]] const std::string& name() const { return name_; }
    void setName(const std::string& val) { name_ = val; }

    [[nodiscard]] const std::string& direction() const { return direction_; }
    void setDirection(const std::string& val) { direction_ = val; }

    [[nodiscard]] const std::string& action() const { return action_; }
    void setAction(const std::string& val) { action_ = val; }

    [[nodiscard]] const std::string& protocol() const { return protocol_; }
    void setProtocol(const std::string& val) { protocol_ = val; }

    [[nodiscard]] const std::string& source() const { return source_; }
    void setSource(const std::string& val) { source_ = val; }

    [[nodiscard]] const std::string& destination() const { return destination_; }
    void setDestination(const std::string& val) { destination_ = val; }

    [[nodiscard]] int port() const { return port_; }
    void setPort(int val) { port_ = val; }

    [[nodiscard]] bool enabled() const { return enabled_; }
    void setEnabled(bool val) { enabled_ = val; }

private:
    std::string name_;
    std::string direction_ = "inbound";
    std::string action_ = "deny";
    std::string protocol_ = "tcp";
    std::string source_;
    std::string destination_;
    int port_ = 0;
    bool enabled_ = true;
};

} // namespace ThreatOne::Database::Models
