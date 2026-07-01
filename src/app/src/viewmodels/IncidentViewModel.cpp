// ThreatOne App - IncidentViewModel Implementation

#include "app/viewmodels/IncidentViewModel.h"

namespace ThreatOne::App {

#ifdef ENABLE_QT_BUILD

IncidentViewModel::IncidentViewModel(QObject* parent)
    : QObject(parent)
    , logger_(ThreatOne::Core::Logger::instance().getModuleLogger("IncidentViewModel")) {
}

IncidentViewModel::~IncidentViewModel() = default;

QString IncidentViewModel::severityFilter() const { return severityFilter_; }
void IncidentViewModel::setSeverityFilter(const QString& filter) {
    severityFilter_ = filter;
    emit dataUpdated();
}
QString IncidentViewModel::statusFilter() const { return statusFilter_; }
void IncidentViewModel::setStatusFilter(const QString& filter) {
    statusFilter_ = filter;
    emit dataUpdated();
}
int IncidentViewModel::incidentCount() const { return incidentCount_; }

void IncidentViewModel::createIncident(const QVariantMap& /*params*/) {
    ++incidentCount_;
    emit incidentCreated();
    emit dataUpdated();
}

void IncidentViewModel::updateStatus(const QString& /*id*/, const QString& /*status*/) {
    emit statusChanged();
    emit dataUpdated();
}

void IncidentViewModel::assignTo(const QString& /*id*/, const QString& /*user*/) {
    emit dataUpdated();
}

void IncidentViewModel::addNote(const QString& /*id*/, const QString& /*text*/) {
    emit dataUpdated();
}

QVariantList IncidentViewModel::getTimeline(const QString& /*id*/) {
    return {};
}

QVariantList IncidentViewModel::getEvidence(const QString& /*id*/) {
    return {};
}

#else // !ENABLE_QT_BUILD

IncidentViewModel::IncidentViewModel()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("IncidentViewModel")) {
}

IncidentViewModel::~IncidentViewModel() = default;

std::string IncidentViewModel::severityFilter() const { return severityFilter_; }
void IncidentViewModel::setSeverityFilter(const std::string& filter) { severityFilter_ = filter; }
std::string IncidentViewModel::statusFilter() const { return statusFilter_; }
void IncidentViewModel::setStatusFilter(const std::string& filter) { statusFilter_ = filter; }
int IncidentViewModel::incidentCount() const { return incidentCount_; }

void IncidentViewModel::createIncident(const std::string& /*params*/) {
    ++incidentCount_;
}

void IncidentViewModel::updateStatus(const std::string& /*id*/, const std::string& /*status*/) {}
void IncidentViewModel::assignTo(const std::string& /*id*/, const std::string& /*user*/) {}
void IncidentViewModel::addNote(const std::string& /*id*/, const std::string& /*text*/) {}

std::vector<std::string> IncidentViewModel::getTimeline(const std::string& /*id*/) {
    return {};
}

std::vector<std::string> IncidentViewModel::getEvidence(const std::string& /*id*/) {
    return {};
}

#endif // ENABLE_QT_BUILD

} // namespace ThreatOne::App
