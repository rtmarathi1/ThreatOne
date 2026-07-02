#pragma once

#include "siem/ISIEMEngine.h"
#include "core/Logger.h"
#include "core/EventBus.h"
#include "core/Event.h"

#include <mutex>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <atomic>

namespace ThreatOne::SIEM {

// Represents a log source that can be collected from
struct LogSource {
    std::string id;
    std::string name;
    std::string type;  // "file", "syslog", "network", "api"
    std::string endpoint;  // path, hostname:port, URL
    bool enabled = true;
};

// Callback invoked when a log is collected
using LogCollectedCallback = std::function<void(const LogEntry&)>;

class LogCollector {
public:
    LogCollector();
    ~LogCollector() = default;

    // Source management
    std::string addSource(const LogSource& source);
    bool removeSource(const std::string& sourceId);
    [[nodiscard]] std::vector<LogSource> getSources() const;

    // Collection control
    void startCollection();
    void stopCollection();
    [[nodiscard]] bool isCollecting() const;

    // Buffer management
    [[nodiscard]] std::vector<LogEntry> getBuffer() const;
    void clearBuffer();
    [[nodiscard]] size_t getBufferSize() const;

    // Direct ingestion (for push-based sources)
    bool collect(const LogEntry& entry);
    bool collectBatch(const std::vector<LogEntry>& entries);

    // Callback registration
    void onLogCollected(LogCollectedCallback callback);

    // Stats
    [[nodiscard]] long getTotalCollected() const;

private:
    std::string generateSourceId();

    mutable std::mutex mutex_;
    std::vector<LogSource> sources_;
    std::vector<LogEntry> buffer_;
    std::vector<LogCollectedCallback> callbacks_;
    std::atomic<bool> collecting_{false};
    std::atomic<long> totalCollected_{0};
    int nextSourceId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::SIEM
