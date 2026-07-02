// ThreatOne App - ScannerViewModel Implementation

#include "app/viewmodels/ScannerViewModel.h"
#include <string>
#include <vector>

namespace ThreatOne::App {

#ifdef ENABLE_QT_BUILD

ScannerViewModel::ScannerViewModel(QObject* parent)
    : QObject(parent)
    , logger_(ThreatOne::Core::Logger::instance().getModuleLogger("ScannerViewModel")) {
    scanTypes_ = QStringList{"Quick Scan", "Full Scan", "Custom Scan", "Rootkit Scan"};
}

ScannerViewModel::~ScannerViewModel() = default;

QStringList ScannerViewModel::scanTypes() const { return scanTypes_; }
QString ScannerViewModel::activeScanType() const { return activeScanType_; }
double ScannerViewModel::scanProgress() const { return scanProgress_; }
int ScannerViewModel::filesScanned() const { return filesScanned_; }
int ScannerViewModel::threatsFound() const { return threatsFound_; }
QString ScannerViewModel::elapsedTime() const { return elapsedTime_; }
QString ScannerViewModel::currentFile() const { return currentFile_; }
bool ScannerViewModel::isScanning() const { return isScanning_; }

void ScannerViewModel::startScan(const QString& type) {
    activeScanType_ = type;
    isScanning_ = true;
    emit scanStarted();
    emit dataUpdated();
}

void ScannerViewModel::pauseScan() {
    isScanning_ = false;
    emit dataUpdated();
}

void ScannerViewModel::resumeScan() {
    isScanning_ = true;
    emit dataUpdated();
}

void ScannerViewModel::stopScan() {
    isScanning_ = false;
    scanProgress_ = 0.0;
    emit scanCompleted();
    emit dataUpdated();
}

QVariantList ScannerViewModel::getScanResults(const QString& /*scanId*/) {
    return {};
}

#else // !ENABLE_QT_BUILD

ScannerViewModel::ScannerViewModel()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("ScannerViewModel")) {
    scanTypes_ = {"Quick Scan", "Full Scan", "Custom Scan", "Rootkit Scan"};
}

ScannerViewModel::~ScannerViewModel() = default;

std::vector<std::string> ScannerViewModel::scanTypes() const { return scanTypes_; }
std::string ScannerViewModel::activeScanType() const { return activeScanType_; }
double ScannerViewModel::scanProgress() const { return scanProgress_; }
int ScannerViewModel::filesScanned() const { return filesScanned_; }
int ScannerViewModel::threatsFound() const { return threatsFound_; }
std::string ScannerViewModel::elapsedTime() const { return elapsedTime_; }
std::string ScannerViewModel::currentFile() const { return currentFile_; }
bool ScannerViewModel::isScanning() const { return isScanning_; }

void ScannerViewModel::startScan(const std::string& type) {
    activeScanType_ = type;
    isScanning_ = true;
}

void ScannerViewModel::pauseScan() {
    isScanning_ = false;
}

void ScannerViewModel::resumeScan() {
    isScanning_ = true;
}

void ScannerViewModel::stopScan() {
    isScanning_ = false;
    scanProgress_ = 0.0;
}

std::vector<std::string> ScannerViewModel::getScanResults(const std::string& /*scanId*/) {
    return {};
}

#endif // ENABLE_QT_BUILD

} // namespace ThreatOne::App
