#pragma once

// Simplified spdlog-compatible logging API
// This is a minimal vendored implementation for ThreatOne

#include <iostream>
#include <string>
#include <memory>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <mutex>

namespace spdlog {

enum class level {
    trace = 0,
    debug = 1,
    info = 2,
    warn = 3,
    err = 4,
    critical = 5,
    off = 6
};

namespace detail {

inline std::string level_to_string(level lvl) {
    switch (lvl) {
        case level::trace:    return "trace";
        case level::debug:    return "debug";
        case level::info:     return "info";
        case level::warn:     return "warn";
        case level::err:      return "error";
        case level::critical: return "critical";
        case level::off:      return "off";
    }
    return "unknown";
}

inline std::string get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf{};
    localtime_r(&time_t_now, &tm_buf);
    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

// Simple format helper - replaces {} with arguments
inline std::string format_impl(const std::string& fmt) {
    return fmt;
}

template<typename T, typename... Args>
inline std::string format_impl(const std::string& fmt, T&& first, Args&&... rest) {
    auto pos = fmt.find("{}");
    if (pos == std::string::npos) return fmt;

    std::ostringstream oss;
    oss << std::forward<T>(first);

    std::string result = fmt.substr(0, pos) + oss.str() + fmt.substr(pos + 2);
    return format_impl(result, std::forward<Args>(rest)...);
}

} // namespace detail

class logger {
public:
    explicit logger(std::string name) : name_(std::move(name)), level_(level::info) {}

    void set_level(level lvl) { level_ = lvl; }
    level get_level() const { return level_; }
    const std::string& name() const { return name_; }

    template<typename... Args>
    void log(level lvl, const std::string& fmt, Args&&... args) {
        if (lvl < level_) return;
        std::string msg = detail::format_impl(fmt, std::forward<Args>(args)...);
        std::lock_guard<std::mutex> lock(mutex_);
        std::cout << "[" << detail::get_timestamp() << "] "
                  << "[" << name_ << "] "
                  << "[" << detail::level_to_string(lvl) << "] "
                  << msg << "\n";
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

private:
    std::string name_;
    level level_;
    std::mutex mutex_;
};

// Global default logger
inline std::shared_ptr<logger>& default_logger() {
    static auto instance = std::make_shared<logger>("default");
    return instance;
}

inline std::shared_ptr<logger> get(const std::string& name) {
    return std::make_shared<logger>(name);
}

inline void set_default_logger(std::shared_ptr<logger> lg) {
    default_logger() = std::move(lg);
}

inline void set_level(level lvl) {
    default_logger()->set_level(lvl);
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
