#pragma once

// ThreatOne App - FirewallViewModel
// Provides firewall rule management and connection monitoring to the QML UI layer.

#include <string>
#include <vector>
#include <memory>

#ifdef ENABLE_QT_BUILD
#include <QObject>
#include <QString>
#include <QStringList>
#include <QVariantList>
#include <QVariantMap>
#endif

#include "core/Logger.h"

namespace ThreatOne::App {

#ifdef ENABLE_QT_BUILD

class FirewallViewModel : public QObject {
    Q_OBJECT

    Q_PROPERTY(QStringList blockedIPs READ blockedIPs NOTIFY dataUpdated)
    Q_PROPERTY(int rulesCount READ rulesCount NOTIFY dataUpdated)
    Q_PROPERTY(int blockedToday READ blockedToday NOTIFY dataUpdated)
    Q_PROPERTY(double bandwidth READ bandwidth NOTIFY dataUpdated)

public:
    explicit FirewallViewModel(QObject* parent = nullptr);
    ~FirewallViewModel() override;

    QStringList blockedIPs() const;
    int rulesCount() const;
    int blockedToday() const;
    double bandwidth() const;

    Q_INVOKABLE void addRule(const QVariantMap& params);
    Q_INVOKABLE void removeRule(const QString& id);
    Q_INVOKABLE void toggleRule(const QString& id);
    Q_INVOKABLE void blockIP(const QString& ip);
    Q_INVOKABLE void unblockIP(const QString& ip);
    Q_INVOKABLE QVariantList getDNSCategories();
    Q_INVOKABLE void setGeoBlocking(const QString& country, bool enabled);

signals:
    void dataUpdated();
    void ruleAdded();
    void ruleRemoved();
    void connectionBlocked();

private:
    ThreatOne::Core::ModuleLogger logger_;
    QStringList blockedIPs_;
    int rulesCount_ = 0;
    int blockedToday_ = 0;
    double bandwidth_ = 0.0;
};

#else // !ENABLE_QT_BUILD

class FirewallViewModel {
public:
    FirewallViewModel();
    ~FirewallViewModel();

    std::vector<std::string> blockedIPs() const;
    int rulesCount() const;
    int blockedToday() const;
    double bandwidth() const;

    void addRule(const std::string& params);
    void removeRule(const std::string& id);
    void toggleRule(const std::string& id);
    void blockIP(const std::string& ip);
    void unblockIP(const std::string& ip);
    std::vector<std::string> getDNSCategories();
    void setGeoBlocking(const std::string& country, bool enabled);

private:
    ThreatOne::Core::ModuleLogger logger_;
    std::vector<std::string> blockedIPs_;
    int rulesCount_ = 0;
    int blockedToday_ = 0;
    double bandwidth_ = 0.0;
};

#endif // ENABLE_QT_BUILD

} // namespace ThreatOne::App
