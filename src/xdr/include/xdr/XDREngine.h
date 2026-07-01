#pragma once

#include "xdr/IXDREngine.h"
#include "core/Logger.h"

namespace ThreatOne::XDR {

class XDREngine : public IXDREngine {
public:
    XDREngine();
    ~XDREngine() override = default;

    std::vector<Correlation> correlateEvents(const std::vector<std::string>& eventIds) override;
    std::vector<Correlation> getCorrelations() override;
    std::string startInvestigation(const std::string& correlationId) override;
    std::vector<TimelineEntry> getTimeline(const std::string& investigationId) override;
    std::vector<Incident> getIncidents() override;

private:
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::XDR
