#pragma once

// ThreatOne App - ReportViewModel
// Provides report generation and management to the QML UI layer.

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

class ReportViewModel : public QObject {
    Q_OBJECT

    Q_PROPERTY(int currentStep READ currentStep NOTIFY dataUpdated)
    Q_PROPERTY(QStringList reportTypes READ reportTypes NOTIFY dataUpdated)

public:
    explicit ReportViewModel(QObject* parent = nullptr);
    ~ReportViewModel() override;

    int currentStep() const;
    QStringList reportTypes() const;

    Q_INVOKABLE void generateReport(const QString& type, const QVariantMap& config);
    Q_INVOKABLE void exportReport(const QString& id, const QString& format);
    Q_INVOKABLE void deleteReport(const QString& id);
    Q_INVOKABLE QVariantList getReportPreview(const QString& id);
    Q_INVOKABLE QVariantList getTemplates();

signals:
    void dataUpdated();
    void reportGenerated();
    void exportComplete();

private:
    ThreatOne::Core::ModuleLogger logger_;
    int currentStep_ = 0;
    QStringList reportTypes_;
};

#else // !ENABLE_QT_BUILD

class ReportViewModel {
public:
    ReportViewModel();
    ~ReportViewModel();

    int currentStep() const;
    std::vector<std::string> reportTypes() const;

    void generateReport(const std::string& type, const std::string& config);
    void exportReport(const std::string& id, const std::string& format);
    void deleteReport(const std::string& id);
    std::vector<std::string> getReportPreview(const std::string& id);
    std::vector<std::string> getTemplates();

private:
    ThreatOne::Core::ModuleLogger logger_;
    int currentStep_ = 0;
    std::vector<std::string> reportTypes_;
};

#endif // ENABLE_QT_BUILD

} // namespace ThreatOne::App
