#include "hids/HIDSEngine.h"

namespace ThreatOne::HIDS {

HIDSEngine::HIDSEngine()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("HIDSEngine")) {
    logger_.info("HIDSEngine initialized (stub)");
}

bool HIDSEngine::startMonitoring() {
    logger_.info("startMonitoring called");
    return true;
}

std::vector<IntegrityEvent> HIDSEngine::getIntegrityEvents() {
    logger_.info("getIntegrityEvents called");
    return {};
}

std::vector<FileChange> HIDSEngine::getFileChanges() {
    logger_.info("getFileChanges called");
    return {};
}

std::vector<PolicyViolation> HIDSEngine::getPolicyViolations() {
    logger_.info("getPolicyViolations called");
    return {};
}

BaselineInfo HIDSEngine::getBaseline() {
    logger_.info("getBaseline called");
    return {"BL-001", "Initial Baseline", "", 0, "Not created"};
}

} // namespace ThreatOne::HIDS
