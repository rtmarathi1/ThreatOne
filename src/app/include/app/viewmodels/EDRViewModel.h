#pragma once

// ThreatOne App - EDRViewModel
// Provides Endpoint Detection and Response data to the QML UI layer.

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

class EDRViewModel : public QObject {
    Q_OBJECT

    Q_PROPERTY(int processCount READ processCount NOTIFY dataUpdated)
    Q_PROPERTY(int alertCount READ alertCount NOTIFY dataUpdated)

public:
    explicit EDRViewModel(QObject* parent = nullptr);
    ~EDRViewModel() override;

    int processCount() const;
    int alertCount() const;

    Q_INVOKABLE void killProcess(int pid);
    Q_INVOKABLE void quarantineFile(const QString& path);
    Q_INVOKABLE QVariantList getProcessTree();
    Q_INVOKABLE QVariantList getFileEvents(const QString& timeRange);
    Q_INVOKABLE void acknowledgeAlert(const QString& id);

signals:
    void dataUpdated();
    void alertTriggered();
    void suspiciousActivity();

private:
    ThreatOne::Core::ModuleLogger logger_;
    int processCount_ = 0;
    int alertCount_ = 0;
};

#else // !ENABLE_QT_BUILD

class EDRViewModel {
public:
    EDRViewModel();
    ~EDRViewModel();

    int processCount() const;
    int alertCount() const;

    void killProcess(int pid);
    void quarantineFile(const std::string& path);
    std::vector<std::string> getProcessTree();
    std::vector<std::string> getFileEvents(const std::string& timeRange);
    void acknowledgeAlert(const std::string& id);

private:
    ThreatOne::Core::ModuleLogger logger_;
    int processCount_ = 0;
    int alertCount_ = 0;
};

#endif // ENABLE_QT_BUILD

} // namespace ThreatOne::App
