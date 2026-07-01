// ThreatOne App - DashboardViewModel Implementation

#include "app/viewmodels/DashboardViewModel.h"

namespace ThreatOne::App {

#ifdef ENABLE_QT_BUILD

DashboardViewModel::DashboardViewModel(QObject* parent)
    : QObject(parent)
    , logger_(ThreatOne::Core::Logger::instance().getModuleLogger("DashboardViewModel")) {
}

DashboardViewModel::~DashboardViewModel() = default;

double DashboardViewModel::securityScore() const { return securityScore_; }
int DashboardViewModel::threatCount() const { return threatCount_; }
int DashboardViewModel::activeScans() const { return activeScans_; }
int DashboardViewModel::openIncidents() const { return openIncidents_; }
int DashboardViewModel::alertCount() const { return alertCount_; }
double DashboardViewModel::complianceScore() const { return complianceScore_; }
int DashboardViewModel::endpointHealthy() const { return endpointHealthy_; }
int DashboardViewModel::endpointWarning() const { return endpointWarning_; }
int DashboardViewModel::endpointCritical() const { return endpointCritical_; }
double DashboardViewModel::cpuUsage() const { return cpuUsage_; }
double DashboardViewModel::memoryUsage() const { return memoryUsage_; }
QString DashboardViewModel::networkStatus() const { return networkStatus_; }
QStringList DashboardViewModel::aiInsights() const { return aiInsights_; }

void DashboardViewModel::refresh() {
    // TODO: Connect to backend engines via ServiceLocator
    emit dataUpdated();
}

QVariantList DashboardViewModel::getRecentAlerts() {
    return {};
}

QVariantList DashboardViewModel::getThreatTimeline() {
    return {};
}

#else // !ENABLE_QT_BUILD

DashboardViewModel::DashboardViewModel()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("DashboardViewModel")) {
}

DashboardViewModel::~DashboardViewModel() = default;

double DashboardViewModel::securityScore() const { return securityScore_; }
int DashboardViewModel::threatCount() const { return threatCount_; }
int DashboardViewModel::activeScans() const { return activeScans_; }
int DashboardViewModel::openIncidents() const { return openIncidents_; }
int DashboardViewModel::alertCount() const { return alertCount_; }
double DashboardViewModel::complianceScore() const { return complianceScore_; }
int DashboardViewModel::endpointHealthy() const { return endpointHealthy_; }
int DashboardViewModel::endpointWarning() const { return endpointWarning_; }
int DashboardViewModel::endpointCritical() const { return endpointCritical_; }
double DashboardViewModel::cpuUsage() const { return cpuUsage_; }
double DashboardViewModel::memoryUsage() const { return memoryUsage_; }
std::string DashboardViewModel::networkStatus() const { return networkStatus_; }
std::vector<std::string> DashboardViewModel::aiInsights() const { return aiInsights_; }

void DashboardViewModel::refresh() {}

std::vector<std::string> DashboardViewModel::getRecentAlerts() {
    return {};
}

std::vector<std::string> DashboardViewModel::getThreatTimeline() {
    return {};
}

#endif // ENABLE_QT_BUILD

} // namespace ThreatOne::App
