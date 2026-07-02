// ThreatOne App - ReportViewModel Implementation

#include "app/viewmodels/ReportViewModel.h"
#include <string>
#include <vector>

namespace ThreatOne::App {

#ifdef ENABLE_QT_BUILD

ReportViewModel::ReportViewModel(QObject* parent)
    : QObject(parent)
    , logger_(ThreatOne::Core::Logger::instance().getModuleLogger("ReportViewModel")) {
    reportTypes_ = QStringList{"Executive Summary", "Compliance", "Incident Report", "Vulnerability Assessment", "Threat Intel"};
}

ReportViewModel::~ReportViewModel() = default;

int ReportViewModel::currentStep() const { return currentStep_; }
QStringList ReportViewModel::reportTypes() const { return reportTypes_; }

void ReportViewModel::generateReport(const QString& /*type*/, const QVariantMap& /*config*/) {
    emit reportGenerated();
    emit dataUpdated();
}

void ReportViewModel::exportReport(const QString& /*id*/, const QString& /*format*/) {
    emit exportComplete();
}

void ReportViewModel::deleteReport(const QString& /*id*/) {
    emit dataUpdated();
}

QVariantList ReportViewModel::getReportPreview(const QString& /*id*/) {
    return {};
}

QVariantList ReportViewModel::getTemplates() {
    return {};
}

#else // !ENABLE_QT_BUILD

ReportViewModel::ReportViewModel()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("ReportViewModel")) {
    reportTypes_ = {"Executive Summary", "Compliance", "Incident Report", "Vulnerability Assessment", "Threat Intel"};
}

ReportViewModel::~ReportViewModel() = default;

int ReportViewModel::currentStep() const { return currentStep_; }
std::vector<std::string> ReportViewModel::reportTypes() const { return reportTypes_; }

void ReportViewModel::generateReport(const std::string& /*type*/, const std::string& /*config*/) {}

void ReportViewModel::exportReport(const std::string& /*id*/, const std::string& /*format*/) {}

void ReportViewModel::deleteReport(const std::string& /*id*/) {}

std::vector<std::string> ReportViewModel::getReportPreview(const std::string& /*id*/) {
    return {};
}

std::vector<std::string> ReportViewModel::getTemplates() {
    return {};
}

#endif // ENABLE_QT_BUILD

} // namespace ThreatOne::App
