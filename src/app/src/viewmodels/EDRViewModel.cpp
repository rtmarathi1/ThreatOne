// ThreatOne App - EDRViewModel Implementation

#include "app/viewmodels/EDRViewModel.h"
#include <string>
#include <vector>

namespace ThreatOne::App {

#ifdef ENABLE_QT_BUILD

EDRViewModel::EDRViewModel(QObject* parent)
    : QObject(parent)
    , logger_(ThreatOne::Core::Logger::instance().getModuleLogger("EDRViewModel")) {
}

EDRViewModel::~EDRViewModel() = default;

int EDRViewModel::processCount() const { return processCount_; }
int EDRViewModel::alertCount() const { return alertCount_; }

void EDRViewModel::killProcess(int /*pid*/) {
    emit dataUpdated();
}

void EDRViewModel::quarantineFile(const QString& /*path*/) {
    emit dataUpdated();
}

QVariantList EDRViewModel::getProcessTree() {
    return {};
}

QVariantList EDRViewModel::getFileEvents(const QString& /*timeRange*/) {
    return {};
}

void EDRViewModel::acknowledgeAlert(const QString& /*id*/) {
    if (alertCount_ > 0) --alertCount_;
    emit dataUpdated();
}

#else // !ENABLE_QT_BUILD

EDRViewModel::EDRViewModel()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("EDRViewModel")) {
}

EDRViewModel::~EDRViewModel() = default;

int EDRViewModel::processCount() const { return processCount_; }
int EDRViewModel::alertCount() const { return alertCount_; }

void EDRViewModel::killProcess(int /*pid*/) {}

void EDRViewModel::quarantineFile(const std::string& /*path*/) {}

std::vector<std::string> EDRViewModel::getProcessTree() {
    return {};
}

std::vector<std::string> EDRViewModel::getFileEvents(const std::string& /*timeRange*/) {
    return {};
}

void EDRViewModel::acknowledgeAlert(const std::string& /*id*/) {
    if (alertCount_ > 0) --alertCount_;
}

#endif // ENABLE_QT_BUILD

} // namespace ThreatOne::App
