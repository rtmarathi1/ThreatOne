#pragma once

#include "hids/IHIDSEngine.h"
#include "core/Logger.h"

namespace ThreatOne::HIDS {

class HIDSEngine : public IHIDSEngine {
public:
    HIDSEngine();
    ~HIDSEngine() override = default;

    bool startMonitoring() override;
    std::vector<IntegrityEvent> getIntegrityEvents() override;
    std::vector<FileChange> getFileChanges() override;
    std::vector<PolicyViolation> getPolicyViolations() override;
    BaselineInfo getBaseline() override;

private:
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::HIDS
