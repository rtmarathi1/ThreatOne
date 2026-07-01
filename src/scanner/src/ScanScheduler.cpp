#include "scanner/ScanScheduler.h"

namespace ThreatOne::Scanner {

ScanScheduler::ScanScheduler(unsigned int threadCount)
    : logger_(Core::Logger::instance().getModuleLogger("ScanScheduler"))
    , threadCount_(threadCount == 0 ? std::max(1u, std::thread::hardware_concurrency()) : threadCount)
    , running_(false)
    , stopping_(false)
    , completed_(0) {
}

ScanScheduler::~ScanScheduler() {
    stop();
}

void ScanScheduler::start() {
    if (running_.load()) return;

    running_ = true;
    stopping_ = false;
    completed_ = 0;

    workers_.reserve(threadCount_);
    for (unsigned int i = 0; i < threadCount_; ++i) {
        workers_.emplace_back(&ScanScheduler::workerLoop, this);
    }

    logger_.info("Scan scheduler started with {} threads", threadCount_);
}

void ScanScheduler::stop() {
    if (!running_.load()) return;

    stopping_ = true;
    condition_.notify_all();

    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }

    workers_.clear();
    running_ = false;
    logger_.info("Scan scheduler stopped, {} jobs completed", completed_.load());
}

void ScanScheduler::submit(ScanJob job) {
    if (!running_.load()) return;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        jobQueue_.push(std::move(job));
    }
    condition_.notify_one();
}

void ScanScheduler::submitBatch(const std::vector<std::filesystem::path>& files,
                                 std::function<void(const std::filesystem::path&)> handler) {
    if (!running_.load()) return;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& file : files) {
            ScanJob job;
            job.filePath = file;
            job.handler = handler;
            jobQueue_.push(std::move(job));
        }
    }
    condition_.notify_all();
}

void ScanScheduler::cancelPending() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::queue<ScanJob> empty;
    jobQueue_.swap(empty);
    logger_.info("Cancelled all pending scan jobs");
}

bool ScanScheduler::isRunning() const {
    return running_.load();
}

size_t ScanScheduler::pendingJobCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return jobQueue_.size();
}

size_t ScanScheduler::completedJobCount() const {
    return completed_.load();
}

unsigned int ScanScheduler::threadCount() const {
    return threadCount_;
}

void ScanScheduler::workerLoop() {
    while (true) {
        ScanJob job;

        {
            std::unique_lock<std::mutex> lock(mutex_);
            condition_.wait(lock, [this] {
                return stopping_.load() || !jobQueue_.empty();
            });

            if (stopping_.load() && jobQueue_.empty()) {
                return;
            }

            if (jobQueue_.empty()) {
                continue;
            }

            job = std::move(jobQueue_.front());
            jobQueue_.pop();
        }

        // Execute the job
        try {
            if (job.handler) {
                job.handler(job.filePath);
            }
        } catch (const std::exception& e) {
            logger_.error("Job failed for {}: {}", job.filePath.string(), e.what());
        }

        completed_.fetch_add(1);
    }
}

} // namespace ThreatOne::Scanner
