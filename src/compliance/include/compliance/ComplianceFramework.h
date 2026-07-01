#pragma once

#include <string>
#include <vector>
#include <map>
#include <optional>
#include <mutex>

#include "compliance/IComplianceEngine.h"
#include "core/Logger.h"

namespace ThreatOne::Compliance {

class ComplianceFramework {
public:
    ComplianceFramework();
    ~ComplianceFramework() = default;

    // Get framework definition by type
    [[nodiscard]] std::optional<FrameworkDefinition> getFramework(Framework type) const;

    // Get all framework definitions
    [[nodiscard]] std::vector<FrameworkDefinition> getAllFrameworks() const;

    // Get framework info (summary)
    [[nodiscard]] std::vector<FrameworkInfo> getFrameworkInfos() const;

    // Get controls for a specific framework
    [[nodiscard]] std::vector<ControlInfo> getControls(Framework type) const;

    // Get controls by category within a framework
    [[nodiscard]] std::vector<ControlInfo> getControlsByCategory(Framework type, const std::string& categoryId) const;

    // Get a specific control by ID
    [[nodiscard]] std::optional<ControlInfo> getControl(Framework type, const std::string& controlId) const;

    // Get categories for a framework
    [[nodiscard]] std::vector<ControlCategory> getCategories(Framework type) const;

    // Get framework name as string
    [[nodiscard]] static std::string frameworkToString(Framework type);

private:
    void initializeFrameworks();
    void addNISTFramework();
    void addISO27001Framework();
    void addSOC2Framework();
    void addHIPAAFramework();
    void addPCIDSSFramework();
    void addGDPRFramework();
    void addCISFramework();

    mutable std::mutex mutex_;
    std::map<Framework, FrameworkDefinition> frameworks_;
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Compliance
