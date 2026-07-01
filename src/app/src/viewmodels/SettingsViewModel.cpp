// ThreatOne App - SettingsViewModel Implementation

#include "app/viewmodels/SettingsViewModel.h"

namespace ThreatOne::App {

#ifdef ENABLE_QT_BUILD

SettingsViewModel::SettingsViewModel(QObject* parent)
    : QObject(parent)
    , logger_(ThreatOne::Core::Logger::instance().getModuleLogger("SettingsViewModel"))
    , language_("en")
    , defaultScanType_("Quick Scan")
    , firewallPolicy_("balanced")
    , appVersion_("1.0.0") {
}

SettingsViewModel::~SettingsViewModel() = default;

QString SettingsViewModel::language() const { return language_; }
void SettingsViewModel::setLanguage(const QString& lang) { language_ = lang; emit settingChanged(); }
bool SettingsViewModel::autoUpdate() const { return autoUpdate_; }
void SettingsViewModel::setAutoUpdate(bool enabled) { autoUpdate_ = enabled; emit settingChanged(); }
QString SettingsViewModel::defaultScanType() const { return defaultScanType_; }
void SettingsViewModel::setDefaultScanType(const QString& type) { defaultScanType_ = type; emit settingChanged(); }
QString SettingsViewModel::firewallPolicy() const { return firewallPolicy_; }
void SettingsViewModel::setFirewallPolicy(const QString& policy) { firewallPolicy_ = policy; emit settingChanged(); }
bool SettingsViewModel::notificationEmail() const { return notificationEmail_; }
void SettingsViewModel::setNotificationEmail(bool enabled) { notificationEmail_ = enabled; emit settingChanged(); }
bool SettingsViewModel::notificationDesktop() const { return notificationDesktop_; }
void SettingsViewModel::setNotificationDesktop(bool enabled) { notificationDesktop_ = enabled; emit settingChanged(); }
QString SettingsViewModel::licenseKey() const { return licenseKey_; }
QString SettingsViewModel::licenseExpiry() const { return licenseExpiry_; }
QString SettingsViewModel::appVersion() const { return appVersion_; }

void SettingsViewModel::save() {
    emit settingChanged();
}

void SettingsViewModel::reset() {
    language_ = "en";
    autoUpdate_ = true;
    defaultScanType_ = "Quick Scan";
    firewallPolicy_ = "balanced";
    notificationEmail_ = true;
    notificationDesktop_ = true;
    emit settingChanged();
}

void SettingsViewModel::importConfig(const QString& /*path*/) {
    emit settingChanged();
}

void SettingsViewModel::exportConfig(const QString& /*path*/) {}

void SettingsViewModel::activateLicense(const QString& key) {
    licenseKey_ = key;
    emit settingChanged();
}

void SettingsViewModel::checkForUpdates() {
    emit updateAvailable();
}

#else // !ENABLE_QT_BUILD

SettingsViewModel::SettingsViewModel()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("SettingsViewModel"))
    , language_("en")
    , defaultScanType_("Quick Scan")
    , firewallPolicy_("balanced")
    , appVersion_("1.0.0") {
}

SettingsViewModel::~SettingsViewModel() = default;

std::string SettingsViewModel::language() const { return language_; }
void SettingsViewModel::setLanguage(const std::string& lang) { language_ = lang; }
bool SettingsViewModel::autoUpdate() const { return autoUpdate_; }
void SettingsViewModel::setAutoUpdate(bool enabled) { autoUpdate_ = enabled; }
std::string SettingsViewModel::defaultScanType() const { return defaultScanType_; }
void SettingsViewModel::setDefaultScanType(const std::string& type) { defaultScanType_ = type; }
std::string SettingsViewModel::firewallPolicy() const { return firewallPolicy_; }
void SettingsViewModel::setFirewallPolicy(const std::string& policy) { firewallPolicy_ = policy; }
bool SettingsViewModel::notificationEmail() const { return notificationEmail_; }
void SettingsViewModel::setNotificationEmail(bool enabled) { notificationEmail_ = enabled; }
bool SettingsViewModel::notificationDesktop() const { return notificationDesktop_; }
void SettingsViewModel::setNotificationDesktop(bool enabled) { notificationDesktop_ = enabled; }
std::string SettingsViewModel::licenseKey() const { return licenseKey_; }
std::string SettingsViewModel::licenseExpiry() const { return licenseExpiry_; }
std::string SettingsViewModel::appVersion() const { return appVersion_; }

void SettingsViewModel::save() {}
void SettingsViewModel::reset() {
    language_ = "en";
    autoUpdate_ = true;
    defaultScanType_ = "Quick Scan";
    firewallPolicy_ = "balanced";
    notificationEmail_ = true;
    notificationDesktop_ = true;
}
void SettingsViewModel::importConfig(const std::string& /*path*/) {}
void SettingsViewModel::exportConfig(const std::string& /*path*/) {}
void SettingsViewModel::activateLicense(const std::string& key) { licenseKey_ = key; }
void SettingsViewModel::checkForUpdates() {}

#endif // ENABLE_QT_BUILD

} // namespace ThreatOne::App
