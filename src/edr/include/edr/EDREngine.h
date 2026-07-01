#pragma once

#include "edr/IEDREngine.h"
#include "core/Logger.h"

namespace ThreatOne::EDR {

class EDREngine : public IEDREngine {
public:
    EDREngine();
    ~EDREngine() override = default;

    bool startCollection() override;
    std::vector<ProcessInfo> getProcesses() override;
    std::vector<FileEvent> getFileEvents() override;
    std::vector<RegistryEvent> getRegistryEvents() override;
    std::vector<PersistenceIndicator> detectPersistence() override;
    std::vector<LateralMovementIndicator> detectLateralMovement() override;
    std::vector<RansomwareIndicator> detectRansomware() override;

private:
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::EDR
