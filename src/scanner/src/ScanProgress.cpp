#include "scanner/ScanProgress.h"

namespace ThreatOne::Scanner {

ScanProgress::ScanProgress()
    : totalFiles_(0)
    , filesScanned_(0)
    , threatsFound_(0)
    , bytesScanned_(0)
    , startTime_(std::chrono::steady_clock::now())
    , logger_(Core::Logger::instance().getModuleLogger("ScanProgress")) {
}

void ScanProgress::reset(uint64_t total) {
    totalFiles_.store(total);
    filesScanned_.store(0);
    threatsFound_.store(0);
    bytesScanned_.store(0);
    startTime_ = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> lock(currentFileMutex_);
        currentFile_.clear();
    }
}

void ScanProgress::incrementScanned() {
    filesScanned_.fetch_add(1);
}

void ScanProgress::incrementThreats() {
    threatsFound_.fetch_add(1);
}

void ScanProgress::addBytes(uint64_t bytes) {
    bytesScanned_.fetch_add(bytes);
}

void ScanProgress::setCurrentFile(const std::string& file) {
    std::lock_guard<std::mutex> lock(currentFileMutex_);
    currentFile_ = file;
}

uint64_t ScanProgress::totalFiles() const {
    return totalFiles_.load();
}

uint64_t ScanProgress::filesScanned() const {
    return filesScanned_.load();
}

uint64_t ScanProgress::threatsFound() const {
    return threatsFound_.load();
}

uint64_t ScanProgress::bytesScanned() const {
    return bytesScanned_.load();
}

double ScanProgress::percentage() const {
    uint64_t total = totalFiles_.load();
    if (total == 0) return 0.0;
    uint64_t scanned = filesScanned_.load();
    return static_cast<double>(scanned) / static_cast<double>(total);
}

double ScanProgress::etaSeconds() const {
    uint64_t scanned = filesScanned_.load();
    if (scanned == 0) return 0.0;

    uint64_t total = totalFiles_.load();
    uint64_t remaining = total > scanned ? total - scanned : 0;
    if (remaining == 0) return 0.0;

    auto now = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(now - startTime_).count();
    double rate = static_cast<double>(scanned) / elapsed;

    if (rate <= 0.0) return 0.0;
    return static_cast<double>(remaining) / rate;
}

std::string ScanProgress::currentFile() const {
    std::lock_guard<std::mutex> lock(currentFileMutex_);
    return currentFile_;
}

double ScanProgress::elapsedSeconds() const {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration<double>(now - startTime_).count();
}

ProgressSnapshot ScanProgress::snapshot() const {
    ProgressSnapshot snap;
    snap.totalFiles = totalFiles_.load();
    snap.filesScanned = filesScanned_.load();
    snap.threatsFound = threatsFound_.load();
    snap.bytesScanned = bytesScanned_.load();
    snap.percentage = percentage();
    snap.etaSeconds = etaSeconds();
    snap.startTime = startTime_;
    snap.elapsedSeconds = elapsedSeconds();
    {
        std::lock_guard<std::mutex> lock(currentFileMutex_);
        snap.currentFile = currentFile_;
    }
    return snap;
}

bool ScanProgress::isComplete() const {
    uint64_t total = totalFiles_.load();
    if (total == 0) return true;
    return filesScanned_.load() >= total;
}

} // namespace ThreatOne::Scanner
