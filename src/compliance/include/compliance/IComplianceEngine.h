#pragma once

#include <string>
#include <vector>

namespace ThreatOne::Compliance {

enum class Framework {
    NIST,
    ISO27001,
    SOC2,
    HIPAA,
    PCI_DSS,
    GDPR,
    CIS
};

struct AuditResult {
    std::string id;
    Framework framework;
    double score = 0.0;
    std::vector<std::string> findings;
    std::string timestamp;
};

struct ControlInfo {
    std::string id;
    std::string name;
    std::string description;
    Framework framework;
    std::string status;
    bool implemented = false;
};

struct FrameworkInfo {
    Framework type;
    std::string name;
    std::string version;
    uint32_t totalControls = 0;
    uint32_t implementedControls = 0;
};

class IComplianceEngine {
public:
    virtual ~IComplianceEngine() = default;

    virtual AuditResult runAudit(Framework framework) = 0;
    virtual std::vector<FrameworkInfo> getFrameworks() = 0;
    virtual std::vector<ControlInfo> getControls(Framework framework) = 0;
    virtual double getComplianceScore(Framework framework) = 0;
    virtual std::string generateReport(Framework framework) = 0;
};

} // namespace ThreatOne::Compliance
