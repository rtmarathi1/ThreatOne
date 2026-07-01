#pragma once

// ThreatOne App - IncidentViewModel
// Provides incident management and tracking data to the QML UI layer.

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

class IncidentViewModel : public QObject {
    Q_OBJECT

    Q_PROPERTY(QString severityFilter READ severityFilter WRITE setSeverityFilter NOTIFY dataUpdated)
    Q_PROPERTY(QString statusFilter READ statusFilter WRITE setStatusFilter NOTIFY dataUpdated)
    Q_PROPERTY(int incidentCount READ incidentCount NOTIFY dataUpdated)

public:
    explicit IncidentViewModel(QObject* parent = nullptr);
    ~IncidentViewModel() override;

    QString severityFilter() const;
    void setSeverityFilter(const QString& filter);
    QString statusFilter() const;
    void setStatusFilter(const QString& filter);
    int incidentCount() const;

    Q_INVOKABLE void createIncident(const QVariantMap& params);
    Q_INVOKABLE void updateStatus(const QString& id, const QString& status);
    Q_INVOKABLE void assignTo(const QString& id, const QString& user);
    Q_INVOKABLE void addNote(const QString& id, const QString& text);
    Q_INVOKABLE QVariantList getTimeline(const QString& id);
    Q_INVOKABLE QVariantList getEvidence(const QString& id);

signals:
    void dataUpdated();
    void incidentCreated();
    void statusChanged();

private:
    ThreatOne::Core::ModuleLogger logger_;
    QString severityFilter_;
    QString statusFilter_;
    int incidentCount_ = 0;
};

#else // !ENABLE_QT_BUILD

class IncidentViewModel {
public:
    IncidentViewModel();
    ~IncidentViewModel();

    std::string severityFilter() const;
    void setSeverityFilter(const std::string& filter);
    std::string statusFilter() const;
    void setStatusFilter(const std::string& filter);
    int incidentCount() const;

    void createIncident(const std::string& params);
    void updateStatus(const std::string& id, const std::string& status);
    void assignTo(const std::string& id, const std::string& user);
    void addNote(const std::string& id, const std::string& text);
    std::vector<std::string> getTimeline(const std::string& id);
    std::vector<std::string> getEvidence(const std::string& id);

private:
    ThreatOne::Core::ModuleLogger logger_;
    std::string severityFilter_;
    std::string statusFilter_;
    int incidentCount_ = 0;
};

#endif // ENABLE_QT_BUILD

} // namespace ThreatOne::App
