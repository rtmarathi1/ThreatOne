#pragma once

// ThreatOne App - SettingsViewModel
// Provides application settings management to the QML UI layer.

#include <string>
#include <vector>
#include <memory>

#ifdef ENABLE_QT_BUILD
#include <QObject>
#include <QString>
#include <QStringList>
#endif

#include "core/Logger.h"

namespace ThreatOne::App {

#ifdef ENABLE_QT_BUILD

class SettingsViewModel : public QObject {
    Q_OBJECT

    Q_PROPERTY(QString language READ language WRITE setLanguage NOTIFY settingChanged)
    Q_PROPERTY(bool autoUpdate READ autoUpdate WRITE setAutoUpdate NOTIFY settingChanged)
    Q_PROPERTY(QString defaultScanType READ defaultScanType WRITE setDefaultScanType NOTIFY settingChanged)
    Q_PROPERTY(QString firewallPolicy READ firewallPolicy WRITE setFirewallPolicy NOTIFY settingChanged)
    Q_PROPERTY(bool notificationEmail READ notificationEmail WRITE setNotificationEmail NOTIFY settingChanged)
    Q_PROPERTY(bool notificationDesktop READ notificationDesktop WRITE setNotificationDesktop NOTIFY settingChanged)
    Q_PROPERTY(QString licenseKey READ licenseKey NOTIFY settingChanged)
    Q_PROPERTY(QString licenseExpiry READ licenseExpiry NOTIFY settingChanged)
    Q_PROPERTY(QString appVersion READ appVersion CONSTANT)

public:
    explicit SettingsViewModel(QObject* parent = nullptr);
    ~SettingsViewModel() override;

    QString language() const;
    void setLanguage(const QString& lang);
    bool autoUpdate() const;
    void setAutoUpdate(bool enabled);
    QString defaultScanType() const;
    void setDefaultScanType(const QString& type);
    QString firewallPolicy() const;
    void setFirewallPolicy(const QString& policy);
    bool notificationEmail() const;
    void setNotificationEmail(bool enabled);
    bool notificationDesktop() const;
    void setNotificationDesktop(bool enabled);
    QString licenseKey() const;
    QString licenseExpiry() const;
    QString appVersion() const;

    Q_INVOKABLE void save();
    Q_INVOKABLE void reset();
    Q_INVOKABLE void importConfig(const QString& path);
    Q_INVOKABLE void exportConfig(const QString& path);
    Q_INVOKABLE void activateLicense(const QString& key);
    Q_INVOKABLE void checkForUpdates();

signals:
    void settingChanged();
    void updateAvailable();

private:
    ThreatOne::Core::ModuleLogger logger_;
    QString language_;
    bool autoUpdate_ = true;
    QString defaultScanType_;
    QString firewallPolicy_;
    bool notificationEmail_ = true;
    bool notificationDesktop_ = true;
    QString licenseKey_;
    QString licenseExpiry_;
    QString appVersion_;
};

#else // !ENABLE_QT_BUILD

class SettingsViewModel {
public:
    SettingsViewModel();
    ~SettingsViewModel();

    std::string language() const;
    void setLanguage(const std::string& lang);
    bool autoUpdate() const;
    void setAutoUpdate(bool enabled);
    std::string defaultScanType() const;
    void setDefaultScanType(const std::string& type);
    std::string firewallPolicy() const;
    void setFirewallPolicy(const std::string& policy);
    bool notificationEmail() const;
    void setNotificationEmail(bool enabled);
    bool notificationDesktop() const;
    void setNotificationDesktop(bool enabled);
    std::string licenseKey() const;
    std::string licenseExpiry() const;
    std::string appVersion() const;

    void save();
    void reset();
    void importConfig(const std::string& path);
    void exportConfig(const std::string& path);
    void activateLicense(const std::string& key);
    void checkForUpdates();

private:
    ThreatOne::Core::ModuleLogger logger_;
    std::string language_;
    bool autoUpdate_ = true;
    std::string defaultScanType_;
    std::string firewallPolicy_;
    bool notificationEmail_ = true;
    bool notificationDesktop_ = true;
    std::string licenseKey_;
    std::string licenseExpiry_;
    std::string appVersion_;
};

#endif // ENABLE_QT_BUILD

} // namespace ThreatOne::App
