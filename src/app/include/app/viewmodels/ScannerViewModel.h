#pragma once

// ThreatOne App - ScannerViewModel
// Provides scan operations and progress data to the QML UI layer.

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

class ScannerViewModel : public QObject {
    Q_OBJECT

    Q_PROPERTY(QStringList scanTypes READ scanTypes NOTIFY dataUpdated)
    Q_PROPERTY(QString activeScanType READ activeScanType NOTIFY dataUpdated)
    Q_PROPERTY(double scanProgress READ scanProgress NOTIFY scanProgressChanged)
    Q_PROPERTY(int filesScanned READ filesScanned NOTIFY scanProgressChanged)
    Q_PROPERTY(int threatsFound READ threatsFound NOTIFY threatDetected)
    Q_PROPERTY(QString elapsedTime READ elapsedTime NOTIFY scanProgressChanged)
    Q_PROPERTY(QString currentFile READ currentFile NOTIFY scanProgressChanged)
    Q_PROPERTY(bool isScanning READ isScanning NOTIFY dataUpdated)

public:
    explicit ScannerViewModel(QObject* parent = nullptr);
    ~ScannerViewModel() override;

    QStringList scanTypes() const;
    QString activeScanType() const;
    double scanProgress() const;
    int filesScanned() const;
    int threatsFound() const;
    QString elapsedTime() const;
    QString currentFile() const;
    bool isScanning() const;

    Q_INVOKABLE void startScan(const QString& type);
    Q_INVOKABLE void pauseScan();
    Q_INVOKABLE void resumeScan();
    Q_INVOKABLE void stopScan();
    Q_INVOKABLE QVariantList getScanResults(const QString& scanId);

signals:
    void dataUpdated();
    void scanStarted();
    void scanProgressChanged(double progress);
    void scanCompleted();
    void threatDetected();

private:
    ThreatOne::Core::ModuleLogger logger_;
    QStringList scanTypes_;
    QString activeScanType_;
    double scanProgress_ = 0.0;
    int filesScanned_ = 0;
    int threatsFound_ = 0;
    QString elapsedTime_;
    QString currentFile_;
    bool isScanning_ = false;
};

#else // !ENABLE_QT_BUILD

class ScannerViewModel {
public:
    ScannerViewModel();
    ~ScannerViewModel();

    std::vector<std::string> scanTypes() const;
    std::string activeScanType() const;
    double scanProgress() const;
    int filesScanned() const;
    int threatsFound() const;
    std::string elapsedTime() const;
    std::string currentFile() const;
    bool isScanning() const;

    void startScan(const std::string& type);
    void pauseScan();
    void resumeScan();
    void stopScan();
    std::vector<std::string> getScanResults(const std::string& scanId);

private:
    ThreatOne::Core::ModuleLogger logger_;
    std::vector<std::string> scanTypes_;
    std::string activeScanType_;
    double scanProgress_ = 0.0;
    int filesScanned_ = 0;
    int threatsFound_ = 0;
    std::string elapsedTime_;
    std::string currentFile_;
    bool isScanning_ = false;
};

#endif // ENABLE_QT_BUILD

} // namespace ThreatOne::App
