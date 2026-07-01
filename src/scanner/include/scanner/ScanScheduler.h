#pragma once

// ThreatOne Scanner - Scan Scheduler
// Thread pool for asynchronous file scanning with configurable concurrency

#include <string>
#include <vector>
#include <queue>
#include <functional>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <filesystem>

#include <core/Logger.h>

namespace ThreatOne::Scanner {

// A scan job represents a unit of work
struct ScanJob {
    std::filesystem::path filePath;
    std::function<void(const std::filesystem::path&)> handler;
};

// Thread pool for processing scan jobs
class ScanScheduler {
public:
    explicit ScanScheduler(unsigned int threadCount = 0);
    ~ScanScheduler();

    // Start the thread pool
    void start();

    // Stop the thread pool (waits for in-progress jobs to complete)
    void stop();

    // Submit a job to the work queue
    void submit(ScanJob job);

    // Submit a batch of file paths with a single handler
    void submitBatch(const std::vector<std::filesystem::path>& files,
                     std::function<void(const std::filesystem::path&)> handler);

    // Cancel all pending jobs (does not cancel in-progress jobs)
    void cancelPending();

    // Query status
    bool isRunning() const;
    size_t pendingJobCount() const;
    size_t completedJobCount() const;
    unsigned int threadCount() const;

private:
    void workerLoop();

    Core::ModuleLogger logger_;
    unsigned int threadCount_;
    std::vector<std::thread> workers_;
    std::queue<ScanJob> jobQueue_;
    mutable std::mutex mutex_;
    std::condition_variable condition_;
    std::atomic<bool> running_;
    std::atomic<bool> stopping_;
    std::atomic<size_t> completed_;
};

} // namespace ThreatOne::Scanner
