#include "edr/TelemetryCollector.h"

#include <fstream>
#include <sstream>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace ThreatOne::EDR {

TelemetryCollector::TelemetryCollector(size_t historySize)
    : logger_(Core::Logger::instance().getModuleLogger("TelemetryCollector"))
    , historySize_(historySize) {
    logger_.info("TelemetryCollector initialized with history size {}", historySize);
}

TelemetryData TelemetryCollector::collectSystemMetrics() {
    std::lock_guard<std::mutex> lock(mutex_);

    TelemetryData data;
    data.timestamp = std::chrono::system_clock::now();

    // Read CPU times
    CpuTimes currentCpu = readCpuTimes();
    if (hasPrevCpuTimes_) {
        uint64_t userDelta = currentCpu.user - prevCpuTimes_.user;
        uint64_t niceDelta = currentCpu.nice - prevCpuTimes_.nice;
        uint64_t systemDelta = currentCpu.system - prevCpuTimes_.system;
        uint64_t idleDelta = currentCpu.idle - prevCpuTimes_.idle;
        uint64_t iowaitDelta = currentCpu.iowait - prevCpuTimes_.iowait;
        uint64_t irqDelta = currentCpu.irq - prevCpuTimes_.irq;
        uint64_t softirqDelta = currentCpu.softirq - prevCpuTimes_.softirq;

        uint64_t totalDelta = userDelta + niceDelta + systemDelta +
            idleDelta + iowaitDelta + irqDelta + softirqDelta;

        if (totalDelta > 0) {
            data.cpuUsagePercent = 100.0 *
                static_cast<double>(totalDelta - idleDelta) /
                static_cast<double>(totalDelta);
            data.cpuUserPercent = 100.0 *
                static_cast<double>(userDelta + niceDelta) /
                static_cast<double>(totalDelta);
            data.cpuSystemPercent = 100.0 *
                static_cast<double>(systemDelta) /
                static_cast<double>(totalDelta);
        }
    }
    prevCpuTimes_ = currentCpu;
    hasPrevCpuTimes_ = true;

    // Read memory info
    TelemetryData memData = readMemoryInfo();
    data.totalMemoryBytes = memData.totalMemoryBytes;
    data.usedMemoryBytes = memData.usedMemoryBytes;
    data.availableMemoryBytes = memData.availableMemoryBytes;
    data.memoryUsagePercent = memData.memoryUsagePercent;

    // Read disk stats
    auto [diskRead, diskWrite] = readDiskStats();
    if (hasPrevCounters_) {
        data.diskReadBytes = diskRead - prevDiskRead_;
        data.diskWriteBytes = diskWrite - prevDiskWrite_;
    }

    // Read network stats
    auto [netRx, netTx] = readNetworkStats();
    if (hasPrevCounters_) {
        data.networkRxBytes = netRx - prevNetRx_;
        data.networkTxBytes = netTx - prevNetTx_;
    }

    prevDiskRead_ = diskRead;
    prevDiskWrite_ = diskWrite;
    prevNetRx_ = netRx;
    prevNetTx_ = netTx;
    hasPrevCounters_ = true;

    // Store in history
    history_.push_back(data);
    if (history_.size() > historySize_) {
        history_.pop_front();
    }

    return data;
}

std::vector<TelemetryData> TelemetryCollector::getHistoricalMetrics(size_t count) const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (count == 0 || count >= history_.size()) {
        return std::vector<TelemetryData>(history_.begin(), history_.end());
    }

    auto startIt = history_.end() - static_cast<std::ptrdiff_t>(count);
    return std::vector<TelemetryData>(startIt, history_.end());
}

std::vector<TelemetryAnomaly> TelemetryCollector::detectAnomalies() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<TelemetryAnomaly> anomalies;

    if (history_.size() < 5) {
        return anomalies; // Need enough data for baseline
    }

    // Calculate baselines for each metric
    std::vector<double> cpuValues, memValues, diskReadValues, diskWriteValues;
    std::vector<double> netRxValues, netTxValues;

    for (const auto& d : history_) {
        cpuValues.push_back(d.cpuUsagePercent);
        memValues.push_back(d.memoryUsagePercent);
        diskReadValues.push_back(static_cast<double>(d.diskReadBytes));
        diskWriteValues.push_back(static_cast<double>(d.diskWriteBytes));
        netRxValues.push_back(static_cast<double>(d.networkRxBytes));
        netTxValues.push_back(static_cast<double>(d.networkTxBytes));
    }

    auto checkAnomaly = [&](const std::string& metric,
                            const std::vector<double>& values,
                            double threshold) {
        if (values.size() < 2) return;
        double mean = calculateMean(values);
        double stddev = calculateStdDev(values, mean);
        double current = values.back();

        if (stddev > 0.0) {
            double deviation = (current - mean) / stddev;
            if (deviation > threshold) {
                TelemetryAnomaly anomaly;
                anomaly.metric = metric;
                anomaly.currentValue = current;
                anomaly.baselineValue = mean;
                anomaly.deviationFactor = deviation;
                anomaly.timestamp = history_.back().timestamp;

                if (deviation > 4.0) {
                    anomaly.severity = "high";
                } else if (deviation > 3.0) {
                    anomaly.severity = "medium";
                } else {
                    anomaly.severity = "low";
                }

                anomalies.push_back(anomaly);
            }
        }
    };

    checkAnomaly("cpu", cpuValues, 2.0);
    checkAnomaly("memory", memValues, 2.0);
    checkAnomaly("disk_read", diskReadValues, 2.0);
    checkAnomaly("disk_write", diskWriteValues, 2.0);
    checkAnomaly("network_rx", netRxValues, 2.0);
    checkAnomaly("network_tx", netTxValues, 2.0);

    return anomalies;
}

void TelemetryCollector::injectMetrics(const TelemetryData& data) {
    std::lock_guard<std::mutex> lock(mutex_);
    history_.push_back(data);
    if (history_.size() > historySize_) {
        history_.pop_front();
    }
}

void TelemetryCollector::clearHistory() {
    std::lock_guard<std::mutex> lock(mutex_);
    history_.clear();
    hasPrevCpuTimes_ = false;
    hasPrevCounters_ = false;
}

TelemetryCollector::CpuTimes TelemetryCollector::readCpuTimes() const {
    CpuTimes times;
    std::ifstream f("/proc/stat");
    if (!f.is_open()) return times;

    std::string line;
    while (std::getline(f, line)) {
        if (line.compare(0, 4, "cpu ") == 0) {
            std::istringstream iss(line.substr(4));
            iss >> times.user >> times.nice >> times.system >> times.idle
                >> times.iowait >> times.irq >> times.softirq;
            break;
        }
    }

    return times;
}

TelemetryData TelemetryCollector::readMemoryInfo() const {
    TelemetryData data;
    std::ifstream f("/proc/meminfo");
    if (!f.is_open()) return data;

    uint64_t memTotal = 0, memFree = 0, memAvailable = 0, buffers = 0, cached = 0;

    std::string line;
    while (std::getline(f, line)) {
        std::istringstream iss(line);
        std::string key;
        uint64_t value;
        iss >> key >> value;

        if (key == "MemTotal:") memTotal = value * 1024;
        else if (key == "MemFree:") memFree = value * 1024;
        else if (key == "MemAvailable:") memAvailable = value * 1024;
        else if (key == "Buffers:") buffers = value * 1024;
        else if (key == "Cached:") cached = value * 1024;
    }

    data.totalMemoryBytes = memTotal;
    data.availableMemoryBytes = memAvailable > 0 ? memAvailable : (memFree + buffers + cached);
    data.usedMemoryBytes = memTotal - data.availableMemoryBytes;

    if (memTotal > 0) {
        data.memoryUsagePercent = 100.0 *
            static_cast<double>(data.usedMemoryBytes) /
            static_cast<double>(memTotal);
    }

    return data;
}

std::pair<uint64_t, uint64_t> TelemetryCollector::readDiskStats() const {
    uint64_t totalRead = 0, totalWrite = 0;
    std::ifstream f("/proc/diskstats");
    if (!f.is_open()) return {0, 0};

    std::string line;
    while (std::getline(f, line)) {
        std::istringstream iss(line);
        uint64_t major, minor;
        std::string name;
        iss >> major >> minor >> name;

        // Only count whole disk devices (sd*, nvme*n*, vd*)
        if (name.find("sd") == 0 || name.find("nvme") == 0 || name.find("vd") == 0) {
            // Skip partitions (names ending in digits for sd/vd)
            if ((name.find("sd") == 0 || name.find("vd") == 0) &&
                name.size() > 3 && std::isdigit(name.back())) {
                continue;
            }

            uint64_t vals[11];
            for (int i = 0; i < 11 && iss >> vals[i]; i++) {}
            // Field 3 (index 2) = sectors read, field 7 (index 6) = sectors written
            // Each sector is 512 bytes
            totalRead += vals[2] * 512;
            totalWrite += vals[6] * 512;
        }
    }

    return {totalRead, totalWrite};
}

std::pair<uint64_t, uint64_t> TelemetryCollector::readNetworkStats() const {
    uint64_t totalRx = 0, totalTx = 0;
    std::ifstream f("/proc/net/dev");
    if (!f.is_open()) return {0, 0};

    std::string line;
    int lineNum = 0;
    while (std::getline(f, line)) {
        lineNum++;
        if (lineNum <= 2) continue; // Skip header lines

        // Format: iface: rx_bytes rx_packets ... tx_bytes tx_packets ...
        auto colonPos = line.find(':');
        if (colonPos == std::string::npos) continue;

        std::string iface = line.substr(0, colonPos);
        // Trim
        auto start = iface.find_first_not_of(" \t");
        if (start != std::string::npos) {
            iface = iface.substr(start);
        }

        // Skip loopback
        if (iface == "lo") continue;

        std::istringstream iss(line.substr(colonPos + 1));
        uint64_t rxBytes, rxPackets, rxErrs, rxDrop, rxFifo, rxFrame, rxCompressed, rxMulticast;
        uint64_t txBytes;
        iss >> rxBytes >> rxPackets >> rxErrs >> rxDrop >> rxFifo >> rxFrame
            >> rxCompressed >> rxMulticast >> txBytes;

        totalRx += rxBytes;
        totalTx += txBytes;
    }

    return {totalRx, totalTx};
}

double TelemetryCollector::calculateMean(const std::vector<double>& values) const {
    if (values.empty()) return 0.0;
    double sum = std::accumulate(values.begin(), values.end(), 0.0);
    return sum / static_cast<double>(values.size());
}

double TelemetryCollector::calculateStdDev(
    const std::vector<double>& values, double mean) const {
    if (values.size() < 2) return 0.0;

    double sumSqDiff = 0.0;
    for (double v : values) {
        double diff = v - mean;
        sumSqDiff += diff * diff;
    }

    return std::sqrt(sumSqDiff / static_cast<double>(values.size() - 1));
}

} // namespace ThreatOne::EDR
