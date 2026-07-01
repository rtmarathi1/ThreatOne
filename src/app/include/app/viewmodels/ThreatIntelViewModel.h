#pragma once

// ThreatOne App - ThreatIntelViewModel
// Provides threat intelligence data and IOC lookups to the QML UI layer.

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

class ThreatIntelViewModel : public QObject {
    Q_OBJECT

    Q_PROPERTY(int feedCount READ feedCount NOTIFY dataUpdated)
    Q_PROPERTY(int iocCount READ iocCount NOTIFY dataUpdated)

public:
    explicit ThreatIntelViewModel(QObject* parent = nullptr);
    ~ThreatIntelViewModel() override;

    int feedCount() const;
    int iocCount() const;

    Q_INVOKABLE QVariantList searchIOC(const QString& type, const QString& value);
    Q_INVOKABLE void refreshFeeds();
    Q_INVOKABLE QVariantList getCVEDetail(const QString& id);
    Q_INVOKABLE QVariantList getMitreDetails(const QString& techniqueId);
    Q_INVOKABLE void runCorrelation();

signals:
    void dataUpdated();
    void newIOCFound();
    void feedUpdated();

private:
    ThreatOne::Core::ModuleLogger logger_;
    int feedCount_ = 0;
    int iocCount_ = 0;
};

#else // !ENABLE_QT_BUILD

class ThreatIntelViewModel {
public:
    ThreatIntelViewModel();
    ~ThreatIntelViewModel();

    int feedCount() const;
    int iocCount() const;

    std::vector<std::string> searchIOC(const std::string& type, const std::string& value);
    void refreshFeeds();
    std::vector<std::string> getCVEDetail(const std::string& id);
    std::vector<std::string> getMitreDetails(const std::string& techniqueId);
    void runCorrelation();

private:
    ThreatOne::Core::ModuleLogger logger_;
    int feedCount_ = 0;
    int iocCount_ = 0;
};

#endif // ENABLE_QT_BUILD

} // namespace ThreatOne::App
