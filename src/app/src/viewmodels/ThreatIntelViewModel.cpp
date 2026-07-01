// ThreatOne App - ThreatIntelViewModel Implementation

#include "app/viewmodels/ThreatIntelViewModel.h"

namespace ThreatOne::App {

#ifdef ENABLE_QT_BUILD

ThreatIntelViewModel::ThreatIntelViewModel(QObject* parent)
    : QObject(parent)
    , logger_(ThreatOne::Core::Logger::instance().getModuleLogger("ThreatIntelViewModel")) {
}

ThreatIntelViewModel::~ThreatIntelViewModel() = default;

int ThreatIntelViewModel::feedCount() const { return feedCount_; }
int ThreatIntelViewModel::iocCount() const { return iocCount_; }

QVariantList ThreatIntelViewModel::searchIOC(const QString& /*type*/, const QString& /*value*/) {
    return {};
}

void ThreatIntelViewModel::refreshFeeds() {
    emit feedUpdated();
    emit dataUpdated();
}

QVariantList ThreatIntelViewModel::getCVEDetail(const QString& /*id*/) {
    return {};
}

QVariantList ThreatIntelViewModel::getMitreDetails(const QString& /*techniqueId*/) {
    return {};
}

void ThreatIntelViewModel::runCorrelation() {
    emit dataUpdated();
}

#else // !ENABLE_QT_BUILD

ThreatIntelViewModel::ThreatIntelViewModel()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("ThreatIntelViewModel")) {
}

ThreatIntelViewModel::~ThreatIntelViewModel() = default;

int ThreatIntelViewModel::feedCount() const { return feedCount_; }
int ThreatIntelViewModel::iocCount() const { return iocCount_; }

std::vector<std::string> ThreatIntelViewModel::searchIOC(const std::string& /*type*/, const std::string& /*value*/) {
    return {};
}

void ThreatIntelViewModel::refreshFeeds() {}

std::vector<std::string> ThreatIntelViewModel::getCVEDetail(const std::string& /*id*/) {
    return {};
}

std::vector<std::string> ThreatIntelViewModel::getMitreDetails(const std::string& /*techniqueId*/) {
    return {};
}

void ThreatIntelViewModel::runCorrelation() {}

#endif // ENABLE_QT_BUILD

} // namespace ThreatOne::App
