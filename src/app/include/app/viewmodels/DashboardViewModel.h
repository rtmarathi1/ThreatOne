#pragma once

// ThreatOne App - DashboardViewModel
// Provides real-time security dashboard data to the QML UI layer.

#include <string>
#include <vector>
#include <memory>

#ifdef ENABLE_QT_BUILD
#include <QObject>
#include <QString>
#include <QStringList>
#include <QVariantList>
#endif

#include "core/Logger.h"

namespace ThreatOne::App {

#ifdef ENABLE_QT_BUILD

class DashboardViewModel : public QObject {
    Q_OBJECT

    Q_PROPERTY(double securityScore READ securityScore NOTIFY dataUpdated)
    Q_PROPERTY(int threatCount READ threatCount NOTIFY dataUpdated)
    Q_PROPERTY(int activeScans READ activeScans NOTIFY dataUpdated)
    Q_PROPERTY(int openIncidents READ openIncidents NOTIFY dataUpdated)
    Q_PROPERTY(int alertCount READ alertCount NOTIFY dataUpdated)
    Q_PROPERTY(double complianceScore READ complianceScore NOTIFY dataUpdated)
    Q_PROPERTY(int endpointHealthy READ endpointHealthy NOTIFY dataUpdated)
    Q_PROPERTY(int endpointWarning READ endpointWarning NOTIFY dataUpdated)
    Q_PROPERTY(int endpointCritical READ endpointCritical NOTIFY dataUpdated)
    Q_PROPERTY(double cpuUsage READ cpuUsage NOTIFY dataUpdated)
    Q_PROPERTY(double memoryUsage READ memoryUsage NOTIFY dataUpdated)
    Q_PROPERTY(QString networkStatus READ networkStatus NOTIFY dataUpdated)
    Q_PROPERTY(QStringList aiInsights READ aiInsights NOTIFY dataUpdated)

public:
    explicit DashboardViewModel(QObject* parent = nullptr);
    ~DashboardViewModel() override;

    double securityScore() const;
    int threatCount() const;
    int activeScans() const;
    int openIncidents() const;
    int alertCount() const;
    double complianceScore() const;
    int endpointHealthy() const;
    int endpointWarning() const;
    int endpointCritical() const;
    double cpuUsage() const;
    double memoryUsage() const;
    QString networkStatus() const;
    QStringList aiInsights() const;

    Q_INVOKABLE void refresh();
    Q_INVOKABLE QVariantList getRecentAlerts();
    Q_INVOKABLE QVariantList getThreatTimeline();

signals:
    void dataUpdated();

private:
    ThreatOne::Core::ModuleLogger logger_;
    double securityScore_ = 0.0;
    int threatCount_ = 0;
    int activeScans_ = 0;
    int openIncidents_ = 0;
    int alertCount_ = 0;
    double complianceScore_ = 0.0;
    int endpointHealthy_ = 0;
    int endpointWarning_ = 0;
    int endpointCritical_ = 0;
    double cpuUsage_ = 0.0;
    double memoryUsage_ = 0.0;
    QString networkStatus_;
    QStringList aiInsights_;
};

#else // !ENABLE_QT_BUILD

class DashboardViewModel {
public:
    DashboardViewModel();
    ~DashboardViewModel();

    double securityScore() const;
    int threatCount() const;
    int activeScans() const;
    int openIncidents() const;
    int alertCount() const;
    double complianceScore() const;
    int endpointHealthy() const;
    int endpointWarning() const;
    int endpointCritical() const;
    double cpuUsage() const;
    double memoryUsage() const;
    std::string networkStatus() const;
    std::vector<std::string> aiInsights() const;

    void refresh();
    std::vector<std::string> getRecentAlerts();
    std::vector<std::string> getThreatTimeline();

private:
    ThreatOne::Core::ModuleLogger logger_;
    double securityScore_ = 0.0;
    int threatCount_ = 0;
    int activeScans_ = 0;
    int openIncidents_ = 0;
    int alertCount_ = 0;
    double complianceScore_ = 0.0;
    int endpointHealthy_ = 0;
    int endpointWarning_ = 0;
    int endpointCritical_ = 0;
    double cpuUsage_ = 0.0;
    double memoryUsage_ = 0.0;
    std::string networkStatus_;
    std::vector<std::string> aiInsights_;
};

#endif // ENABLE_QT_BUILD

} // namespace ThreatOne::App
