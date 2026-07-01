// ThreatOne App - FirewallViewModel Implementation

#include "app/viewmodels/FirewallViewModel.h"

#include <algorithm>

namespace ThreatOne::App {

#ifdef ENABLE_QT_BUILD

FirewallViewModel::FirewallViewModel(QObject* parent)
    : QObject(parent)
    , logger_(ThreatOne::Core::Logger::instance().getModuleLogger("FirewallViewModel")) {
}

FirewallViewModel::~FirewallViewModel() = default;

QStringList FirewallViewModel::blockedIPs() const { return blockedIPs_; }
int FirewallViewModel::rulesCount() const { return rulesCount_; }
int FirewallViewModel::blockedToday() const { return blockedToday_; }
double FirewallViewModel::bandwidth() const { return bandwidth_; }

void FirewallViewModel::addRule(const QVariantMap& /*params*/) {
    ++rulesCount_;
    emit ruleAdded();
    emit dataUpdated();
}

void FirewallViewModel::removeRule(const QString& /*id*/) {
    if (rulesCount_ > 0) --rulesCount_;
    emit ruleRemoved();
    emit dataUpdated();
}

void FirewallViewModel::toggleRule(const QString& /*id*/) {
    emit dataUpdated();
}

void FirewallViewModel::blockIP(const QString& ip) {
    blockedIPs_.append(ip);
    emit connectionBlocked();
    emit dataUpdated();
}

void FirewallViewModel::unblockIP(const QString& ip) {
    blockedIPs_.removeAll(ip);
    emit dataUpdated();
}

QVariantList FirewallViewModel::getDNSCategories() {
    return {};
}

void FirewallViewModel::setGeoBlocking(const QString& /*country*/, bool /*enabled*/) {
    emit dataUpdated();
}

#else // !ENABLE_QT_BUILD

FirewallViewModel::FirewallViewModel()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("FirewallViewModel")) {
}

FirewallViewModel::~FirewallViewModel() = default;

std::vector<std::string> FirewallViewModel::blockedIPs() const { return blockedIPs_; }
int FirewallViewModel::rulesCount() const { return rulesCount_; }
int FirewallViewModel::blockedToday() const { return blockedToday_; }
double FirewallViewModel::bandwidth() const { return bandwidth_; }

void FirewallViewModel::addRule(const std::string& /*params*/) {
    ++rulesCount_;
}

void FirewallViewModel::removeRule(const std::string& /*id*/) {
    if (rulesCount_ > 0) --rulesCount_;
}

void FirewallViewModel::toggleRule(const std::string& /*id*/) {}

void FirewallViewModel::blockIP(const std::string& ip) {
    blockedIPs_.push_back(ip);
}

void FirewallViewModel::unblockIP(const std::string& ip) {
    blockedIPs_.erase(
        std::remove(blockedIPs_.begin(), blockedIPs_.end(), ip),
        blockedIPs_.end());
}

std::vector<std::string> FirewallViewModel::getDNSCategories() {
    return {};
}

void FirewallViewModel::setGeoBlocking(const std::string& /*country*/, bool /*enabled*/) {}

#endif // ENABLE_QT_BUILD

} // namespace ThreatOne::App
