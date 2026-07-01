#pragma once

#include "siem/ISIEMEngine.h"
#include "core/Logger.h"

namespace ThreatOne::SIEM {

class SIEMEngine : public ISIEMEngine {
public:
    SIEMEngine();
    ~SIEMEngine() override = default;

    bool ingestLog(const LogEntry& entry) override;
    std::vector<LogEntry> searchLogs(const std::string& query) override;
    std::string createAlert(const SIEMAlert& alert) override;
    std::vector<SIEMAlert> getAlerts() override;
    std::string createRule(const SIEMRule& rule) override;
    std::vector<SIEMRule> getRules() override;

private:
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::SIEM
