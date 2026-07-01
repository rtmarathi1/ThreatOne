#pragma once

// Production-quality spdlog-compatible logging library for ThreatOne
// Features: async logging with lock-free ring buffer, multiple sinks,
// configurable format patterns, flush policies, thread-safe design.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace spdlog {

// ============================================================================
// Log levels
// ============================================================================
enum class level {
    trace = 0,
    debug = 1,
    info = 2,
    warn = 3,
    err = 4,
    critical = 5,
    off = 6
};

// ============================================================================
// Forward declarations
// ============================================================================
class logger;

namespace detail {

inline const char* level_to_short_str(level lvl) {
    switch (lvl) {
        case level::trace:    return "trace";
        case level::debug:    return "debug";
        case level::info:     return "info";
        case level::warn:     return "warning";
        case level::err:      return "error";
        case level::critical: return "critical";
        case level::off:      return "off";
    }
    return "unknown";
}

// Format argument to string using ostringstream
template<typename T>
inline std::string to_string_arg(T&& val) {
    std::ostringstream oss;
    oss << std::forward<T>(val);
    return oss.str();
}

// Replace {} placeholders with arguments
inline std::string format_impl(const std::string& fmt) {
    return fmt;
}

template<typename T, typename... Args>
inline std::string format_impl(const std::string& fmt, T&& first, Args&&... rest) {
    auto pos = fmt.find("{}");
    if (pos == std::string::npos) return fmt;
    std::string result;
    result.reserve(fmt.size() + 32);
    result.append(fmt, 0, pos);
    result.append(to_string_arg(std::forward<T>(first)));
    result.append(fmt, pos + 2, std::string::npos);
    return format_impl(result, std::forward<Args>(rest)...);
}

// Log message structure
struct log_msg {
    level lvl{level::info};
    std::string logger_name;
    std::string payload;
    std::chrono::system_clock::time_point time_point;
    std::thread::id thread_id;

    log_msg() = default;
    log_msg(level l, std::string name, std::string msg)
        : lvl(l)
        , logger_name(std::move(name))
        , payload(std::move(msg))
        , time_point(std::chrono::system_clock::now())
        , thread_id(std::this_thread::get_id()) {}
};

// ============================================================================
// Format pattern support
// ============================================================================
inline std::string format_log_msg(const log_msg& msg, const std::string& pattern) {
    std::string result;
    result.reserve(pattern.size() + msg.payload.size() + 64);

    auto tt = std::chrono::system_clock::to_time_t(msg.time_point);
    std::tm tm_buf{};
    localtime_r(&tt, &tm_buf);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        msg.time_point.time_since_epoch()) % 1000;

    for (std::size_t i = 0; i < pattern.size(); ++i) {
        if (pattern[i] == '%' && i + 1 < pattern.size()) {
            char spec = pattern[i + 1];
            ++i;
            switch (spec) {
                case 'Y': {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "%04d", tm_buf.tm_year + 1900);
                    result.append(buf);
                    break;
                }
                case 'm': {
                    char buf[4];
                    std::snprintf(buf, sizeof(buf), "%02d", tm_buf.tm_mon + 1);
                    result.append(buf);
                    break;
                }
                case 'd': {
                    char buf[4];
                    std::snprintf(buf, sizeof(buf), "%02d", tm_buf.tm_mday);
                    result.append(buf);
                    break;
                }
                case 'H': {
                    char buf[4];
                    std::snprintf(buf, sizeof(buf), "%02d", tm_buf.tm_hour);
                    result.append(buf);
                    break;
                }
                case 'M': {
                    char buf[4];
                    std::snprintf(buf, sizeof(buf), "%02d", tm_buf.tm_min);
                    result.append(buf);
                    break;
                }
                case 'S': {
                    char buf[4];
                    std::snprintf(buf, sizeof(buf), "%02d", tm_buf.tm_sec);
                    result.append(buf);
                    break;
                }
                case 'e': {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "%03d",
                                  static_cast<int>(ms.count()));
                    result.append(buf);
                    break;
                }
                case 'n':
                    result.append(msg.logger_name);
                    break;
                case 'l':
                    result.append(level_to_short_str(msg.lvl));
                    break;
                case 't': {
                    std::ostringstream oss;
                    oss << msg.thread_id;
                    result.append(oss.str());
                    break;
                }
                case 'v':
                    result.append(msg.payload);
                    break;
                case 's':
                    // source file - not available in this context
                    break;
                case '#':
                    // line number - not available in this context
                    break;
                default:
                    result.push_back('%');
                    result.push_back(spec);
                    break;
            }
        } else {
            result.push_back(pattern[i]);
        }
    }
    return result;
}

// ============================================================================
// Lock-free ring buffer for async logging
// ============================================================================
template<typename T>
class ring_buffer {
public:
    explicit ring_buffer(std::size_t capacity = 8192)
        : capacity_(next_power_of_two(capacity))
        , mask_(capacity_ - 1)
        , buffer_(new T[capacity_])
        , head_(0)
        , tail_(0) {}

    ~ring_buffer() { delete[] buffer_; }

    ring_buffer(const ring_buffer&) = delete;
    ring_buffer& operator=(const ring_buffer&) = delete;

    bool try_push(const T& item) {
        auto h = head_.load(std::memory_order_relaxed);
        auto next_h = (h + 1) & mask_;
        if (next_h == tail_.load(std::memory_order_acquire)) {
            return false; // full
        }
        buffer_[h] = item;
        head_.store(next_h, std::memory_order_release);
        return true;
    }

    bool try_push(T&& item) {
        auto h = head_.load(std::memory_order_relaxed);
        auto next_h = (h + 1) & mask_;
        if (next_h == tail_.load(std::memory_order_acquire)) {
            return false; // full
        }
        buffer_[h] = std::move(item);
        head_.store(next_h, std::memory_order_release);
        return true;
    }

    bool try_pop(T& item) {
        auto t = tail_.load(std::memory_order_relaxed);
        if (t == head_.load(std::memory_order_acquire)) {
            return false; // empty
        }
        item = std::move(buffer_[t]);
        tail_.store((t + 1) & mask_, std::memory_order_release);
        return true;
    }

    bool empty() const {
        return tail_.load(std::memory_order_acquire) ==
               head_.load(std::memory_order_acquire);
    }

    std::size_t capacity() const { return capacity_; }

private:
    static std::size_t next_power_of_two(std::size_t v) {
        if (v == 0) return 1;
        v--;
        v |= v >> 1;
        v |= v >> 2;
        v |= v >> 4;
        v |= v >> 8;
        v |= v >> 16;
        v |= v >> 32;
        return v + 1;
    }

    std::size_t capacity_;
    std::size_t mask_;
    T* buffer_;
    alignas(64) std::atomic<std::size_t> head_;
    alignas(64) std::atomic<std::size_t> tail_;
};

} // namespace detail

// ============================================================================
// Sink interface (abstract base class)
// ============================================================================
namespace sinks {

class sink {
public:
    virtual ~sink() = default;

    virtual void log(const detail::log_msg& msg) = 0;
    virtual void flush() = 0;

    void set_level(level lvl) { level_.store(lvl, std::memory_order_relaxed); }
    level get_level() const { return level_.load(std::memory_order_relaxed); }

    bool should_log(level msg_level) const {
        return msg_level >= level_.load(std::memory_order_relaxed);
    }

    void set_pattern(const std::string& pattern) {
        std::lock_guard<std::mutex> lock(pattern_mutex_);
        pattern_ = pattern;
    }

    std::string get_pattern() const {
        std::lock_guard<std::mutex> lock(pattern_mutex_);
        return pattern_;
    }

protected:
    std::string format(const detail::log_msg& msg) const {
        std::lock_guard<std::mutex> lock(pattern_mutex_);
        return detail::format_log_msg(msg, pattern_);
    }

    std::atomic<level> level_{level::trace};
    mutable std::mutex pattern_mutex_;
    std::string pattern_ = "[%Y-%m-%d %H:%M:%S.%e] [%n] [%l] %v";
};

} // namespace sinks

// ============================================================================
// Logger class
// ============================================================================
class logger {
public:
    explicit logger(std::string name)
        : name_(std::move(name))
        , level_(level::info)
        , flush_level_(level::off) {}

    logger(std::string name, std::shared_ptr<sinks::sink> single_sink)
        : name_(std::move(name))
        , level_(level::info)
        , flush_level_(level::off) {
        sinks_.push_back(std::move(single_sink));
    }

    logger(std::string name, std::vector<std::shared_ptr<sinks::sink>> sink_list)
        : name_(std::move(name))
        , sinks_(std::move(sink_list))
        , level_(level::info)
        , flush_level_(level::off) {}

    virtual ~logger() = default;

    const std::string& name() const { return name_; }

    void set_level(level lvl) { level_.store(lvl, std::memory_order_relaxed); }
    level get_level() const { return level_.load(std::memory_order_relaxed); }

    bool should_log(level msg_level) const {
        return msg_level >= level_.load(std::memory_order_relaxed);
    }

    void set_pattern(const std::string& pattern) {
        for (auto& s : sinks_) {
            if (s) s->set_pattern(pattern);
        }
    }

    void flush_on(level lvl) {
        flush_level_.store(lvl, std::memory_order_relaxed);
    }

    std::vector<std::shared_ptr<sinks::sink>>& sinks() { return sinks_; }
    const std::vector<std::shared_ptr<sinks::sink>>& sinks() const { return sinks_; }

    void flush() {
        for (auto& s : sinks_) {
            if (s) s->flush();
        }
    }

    template<typename... Args>
    void log(level lvl, const std::string& fmt, Args&&... args) {
        if (!should_log(lvl)) return;
        std::string formatted = detail::format_impl(fmt, std::forward<Args>(args)...);
        detail::log_msg msg(lvl, name_, std::move(formatted));
        sink_it_(msg);
        if (lvl >= flush_level_.load(std::memory_order_relaxed)) {
            flush();
        }
    }

    template<typename... Args>
    void trace(const std::string& fmt, Args&&... args) {
        log(level::trace, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void debug(const std::string& fmt, Args&&... args) {
        log(level::debug, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void info(const std::string& fmt, Args&&... args) {
        log(level::info, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void warn(const std::string& fmt, Args&&... args) {
        log(level::warn, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void error(const std::string& fmt, Args&&... args) {
        log(level::err, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void critical(const std::string& fmt, Args&&... args) {
        log(level::critical, fmt, std::forward<Args>(args)...);
    }

protected:
    virtual void sink_it_(const detail::log_msg& msg) {
        for (auto& s : sinks_) {
            if (s && s->should_log(msg.lvl)) {
                s->log(msg);
            }
        }
    }

    std::string name_;
    std::vector<std::shared_ptr<sinks::sink>> sinks_;
    std::atomic<level> level_;
    std::atomic<level> flush_level_;
};

// ============================================================================
// Async logger with ring buffer backend
// ============================================================================
class async_logger : public logger {
public:
    async_logger(std::string name, std::vector<std::shared_ptr<sinks::sink>> sink_list,
                 std::size_t buffer_size = 8192)
        : logger(std::move(name), std::move(sink_list))
        , ring_buffer_(buffer_size)
        , running_(true) {
        worker_ = std::thread([this] { worker_loop(); });
    }

    ~async_logger() override {
        running_.store(false, std::memory_order_release);
        cv_.notify_one();
        if (worker_.joinable()) {
            worker_.join();
        }
        // Drain remaining messages
        detail::log_msg msg;
        while (ring_buffer_.try_pop(msg)) {
            for (auto& s : sinks_) {
                if (s && s->should_log(msg.lvl)) {
                    s->log(msg);
                }
            }
        }
    }

    void flush() {
        // Signal flush and wait for drain
        std::unique_lock<std::mutex> lock(flush_mutex_);
        flush_requested_.store(true, std::memory_order_release);
        cv_.notify_one();
        flush_cv_.wait(lock, [this] {
            return !flush_requested_.load(std::memory_order_acquire);
        });
    }

protected:
    void sink_it_(const detail::log_msg& msg) override {
        // Try to push; if full, block briefly
        while (!ring_buffer_.try_push(msg)) {
            std::this_thread::yield();
        }
        cv_.notify_one();
    }

private:
    void worker_loop() {
        detail::log_msg msg;
        while (running_.load(std::memory_order_acquire)) {
            {
                std::unique_lock<std::mutex> lock(cv_mutex_);
                cv_.wait_for(lock, std::chrono::milliseconds(10), [this] {
                    return !ring_buffer_.empty() ||
                           !running_.load(std::memory_order_acquire) ||
                           flush_requested_.load(std::memory_order_acquire);
                });
            }

            while (ring_buffer_.try_pop(msg)) {
                for (auto& s : sinks_) {
                    if (s && s->should_log(msg.lvl)) {
                        s->log(msg);
                    }
                }
            }

            if (flush_requested_.load(std::memory_order_acquire)) {
                for (auto& s : sinks_) {
                    if (s) s->flush();
                }
                flush_requested_.store(false, std::memory_order_release);
                flush_cv_.notify_all();
            }
        }
    }

    detail::ring_buffer<detail::log_msg> ring_buffer_;
    std::atomic<bool> running_;
    std::thread worker_;
    std::mutex cv_mutex_;
    std::condition_variable cv_;
    std::mutex flush_mutex_;
    std::condition_variable flush_cv_;
    std::atomic<bool> flush_requested_{false};
};

// ============================================================================
// Registry - manages named loggers
// ============================================================================
namespace detail {

class registry {
public:
    static registry& instance() {
        static registry inst;
        return inst;
    }

    void register_logger(std::shared_ptr<logger> lg) {
        std::lock_guard<std::mutex> lock(mutex_);
        loggers_[lg->name()] = std::move(lg);
    }

    std::shared_ptr<logger> get(const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = loggers_.find(name);
        if (it != loggers_.end()) {
            return it->second;
        }
        return nullptr;
    }

    void drop(const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex_);
        loggers_.erase(name);
    }

    void drop_all() {
        std::lock_guard<std::mutex> lock(mutex_);
        loggers_.clear();
    }

    std::shared_ptr<logger>& default_logger() {
        return default_logger_;
    }

    void set_default_logger(std::shared_ptr<logger> lg) {
        std::lock_guard<std::mutex> lock(mutex_);
        default_logger_ = std::move(lg);
    }

private:
    registry() {
        default_logger_ = std::make_shared<logger>("default");
    }

    std::mutex mutex_;
    std::unordered_map<std::string, std::shared_ptr<logger>> loggers_;
    std::shared_ptr<logger> default_logger_;
};

} // namespace detail

// ============================================================================
// Free functions - global API
// ============================================================================
inline std::shared_ptr<logger>& default_logger() {
    return detail::registry::instance().default_logger();
}

inline std::shared_ptr<logger> get(const std::string& name) {
    return detail::registry::instance().get(name);
}

inline void register_logger(std::shared_ptr<logger> lg) {
    detail::registry::instance().register_logger(std::move(lg));
}

inline void set_default_logger(std::shared_ptr<logger> lg) {
    detail::registry::instance().set_default_logger(std::move(lg));
}

inline void set_level(level lvl) {
    default_logger()->set_level(lvl);
}

inline void set_pattern(const std::string& pattern) {
    default_logger()->set_pattern(pattern);
}

inline void flush_on(level lvl) {
    default_logger()->flush_on(lvl);
}

inline void drop(const std::string& name) {
    detail::registry::instance().drop(name);
}

inline void drop_all() {
    detail::registry::instance().drop_all();
}

template<typename... Args>
inline void trace(const std::string& fmt, Args&&... args) {
    default_logger()->trace(fmt, std::forward<Args>(args)...);
}

template<typename... Args>
inline void debug(const std::string& fmt, Args&&... args) {
    default_logger()->debug(fmt, std::forward<Args>(args)...);
}

template<typename... Args>
inline void info(const std::string& fmt, Args&&... args) {
    default_logger()->info(fmt, std::forward<Args>(args)...);
}

template<typename... Args>
inline void warn(const std::string& fmt, Args&&... args) {
    default_logger()->warn(fmt, std::forward<Args>(args)...);
}

template<typename... Args>
inline void error(const std::string& fmt, Args&&... args) {
    default_logger()->error(fmt, std::forward<Args>(args)...);
}

template<typename... Args>
inline void critical(const std::string& fmt, Args&&... args) {
    default_logger()->critical(fmt, std::forward<Args>(args)...);
}

} // namespace spdlog
