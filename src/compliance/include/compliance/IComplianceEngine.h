#pragma once

#include <string>
#include <vector>
#include <map>
#include <optional>
#include <cstdint>
#include <utility>

namespace ThreatOne::Compliance {

// Framework enum representing supported compliance frameworks
enum class Framework {
    NIST,
    ISO27001,
    SOC2,
    HIPAA,
    PCI_DSS,
    GDPR,
    CIS
};

// Finding status from a compliance scan
enum class FindingStatus {
    Pass,
    Fail,
    Warning,
    NotApplicable
};

// Severity levels for findings
enum class FindingSeverity {
    Low,
    Medium,
    High,
    Critical
};

// Evidence types
enum class EvidenceType {
    ConfigFile,
    LogEntry,
    PolicyDocument,
    ScanResult
};

// Remediation status
enum class RemediationStatus {
    Open,
    InProgress,
    Resolved,
    Overdue
};

// A single control requirement within a framework
struct ControlRequirement {
    std::string id;
    std::string description;
    std::vector<EvidenceType> requiredEvidence;
};

// A control within a framework
struct ControlInfo {
    std::string id;
    std::string name;
    std::string description;
    Framework framework;
    std::string categoryId;
    std::string status;
    bool implemented = false;
    std::vector<ControlRequirement> requirements;
};

// A category grouping controls within a framework
struct ControlCategory {
    std::string id;
    std::string name;
    std::string description;
    std::vector<ControlInfo> controls;
};

// Framework definition containing categories and controls
struct FrameworkDefinition {
    Framework type;
    std::string name;
    std::string version;
    std::vector<ControlCategory> categories;
};

// Information about a framework (summary)
struct FrameworkInfo {
    Framework type;
    std::string name;
    std::string version;
    uint32_t totalControls = 0;
    uint32_t implementedControls = 0;
};

// A finding from a compliance scan
struct ComplianceFinding {
    std::string id;
    std::string controlId;
    Framework framework;
    FindingStatus status;
    FindingSeverity severity;
    std::string description;
    std::string evidenceReference;
    std::string timestamp;
};

// Score for a specific category
struct CategoryScore {
    std::string categoryId;
    std::string categoryName;
    double score = 0.0;
    uint32_t totalControls = 0;
    uint32_t passingControls = 0;
};

// Score for a framework
struct FrameworkScore {
    Framework framework;
    double overallScore = 0.0;
    std::vector<CategoryScore> categoryScores;
    std::string timestamp;
};

// Score history entry for trend tracking
struct ScoreHistoryEntry {
    double score = 0.0;
    std::string timestamp;
};

// Evidence record linked to a control
struct EvidenceRecord {
    std::string id;
    std::string controlId;
    Framework framework;
    EvidenceType type;
    std::string title;
    std::string content;
    std::string collectedAt;
    bool verified = false;
};

// Remediation item for a failed control
struct RemediationItem {
    std::string id;
    std::string controlId;
    Framework framework;
    std::string title;
    std::string description;
    std::string owner;
    std::string dueDate;
    RemediationStatus status = RemediationStatus::Open;
    std::string createdAt;
    std::string updatedAt;
    std::vector<std::string> verificationSteps;
    std::vector<std::pair<RemediationStatus, std::string>> statusHistory;
};

// Audit result from running a compliance audit
struct AuditResult {
    std::string id;
    Framework framework;
    double score = 0.0;
    std::vector<ComplianceFinding> findings;
    std::string timestamp;
};

// Interface for the compliance engine
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
