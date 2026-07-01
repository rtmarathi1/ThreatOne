#pragma once

// ThreatOne Core - Logging facade wrapping spdlog
// Provides module-tagged logging with configurable sinks and levels

#include <string>
#include <string_view>
#include <memory>
#include <unordered_map>
#include <mutex>

#include <spdlog/spdlog.h>

namespace ThreatOne::Core {

// Log level enum (mirrors spdlog for consistency)
enum class LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
    Critical = 5,
    Off = 6
};

// Configuration for the logging system
struct LogConfig {
    LogLevel consoleLevel = LogLevel::Info;
    LogLevel fileLevel = LogLevel::Debug;
    std::string logDirectory = "logs";
    std::string filePattern = "threatone.log";
    std::size_t maxFileSize = 10 * 1024 * 1024; // 10MB
    std::size_t maxFiles = 5;
    bool enableConsole = true;
    bool enableFile = false;
    std::string pattern = "[%Y-%m-%d %H:%M:%S.%e] [%n] [%l] %v";
};

// Module-scoped logger that tags all messages with its module name
class ModuleLogger {
public:
    explicit ModuleLogger(std::string moduleName);

    template<typename... Args>
    void trace(const std::string& fmt, Args&&... args) const {
        if (logger_) {
            logger_->trace(fmt, std::forward<Args>(args)...);
        }
    }

    template<typename... Args>
    void debug(const std::string& fmt, Args&&... args) const {
        if (logger_) {
            logger_->debug(fmt, std::forward<Args>(args)...);
        }
    }

    template<typename... Args>
    void info(const std::string& fmt, Args&&... args) const {
        if (logger_) {
            logger_->info(fmt, std::forward<Args>(args)...);
        }
    }

    template<typename... Args>
    void warn(const std::string& fmt, Args&&... args) const {
        if (logger_) {
            logger_->warn(fmt, std::forward<Args>(args)...);
        }
    }

    template<typename... Args>
    void error(const std::string& fmt, Args&&... args) const {
        if (logger_) {
            logger_->error(fmt, std::forward<Args>(args)...);
        }
    }

    template<typename... Args>
    void critical(const std::string& fmt, Args&&... args) const {
        if (logger_) {
            logger_->critical(fmt, std::forward<Args>(args)...);
        }
    }

    void setLevel(LogLevel level);
    [[nodiscard]] LogLevel getLevel() const;
    [[nodiscard]] const std::string& moduleName() const { return moduleName_; }

private:
    std::string moduleName_;
    std::shared_ptr<spdlog::logger> logger_;
};

// Central logging manager (singleton)
class Logger {
public:
    // Singleton access
    static Logger& instance();

    // Initialization
    void initialize(const LogConfig& config = LogConfig{});
    void shutdown();

    // Get or create a module-scoped logger
    [[nodiscard]] ModuleLogger getModuleLogger(const std::string& moduleName);

    // Global log level control
    void setGlobalLevel(LogLevel level);
    [[nodiscard]] LogLevel getGlobalLevel() const;

    // Set log level for a specific module
    void setModuleLevel(const std::string& moduleName, LogLevel level);

    // Direct logging on the default logger
    template<typename... Args>
    void trace(const std::string& fmt, Args&&... args) {
        if (defaultLogger_) {
            defaultLogger_->trace(fmt, std::forward<Args>(args)...);
        }
    }

    template<typename... Args>
    void debug(const std::string& fmt, Args&&... args) {
        if (defaultLogger_) {
            defaultLogger_->debug(fmt, std::forward<Args>(args)...);
        }
    }

    template<typename... Args>
    void info(const std::string& fmt, Args&&... args) {
        if (defaultLogger_) {
            defaultLogger_->info(fmt, std::forward<Args>(args)...);
        }
    }

    template<typename... Args>
    void warn(const std::string& fmt, Args&&... args) {
        if (defaultLogger_) {
            defaultLogger_->warn(fmt, std::forward<Args>(args)...);
        }
    }

    template<typename... Args>
    void error(const std::string& fmt, Args&&... args) {
        if (defaultLogger_) {
            defaultLogger_->error(fmt, std::forward<Args>(args)...);
        }
    }

    template<typename... Args>
    void critical(const std::string& fmt, Args&&... args) {
        if (defaultLogger_) {
            defaultLogger_->critical(fmt, std::forward<Args>(args)...);
        }
    }

    // Log level conversion utility
    static spdlog::level toSpdlogLevel(LogLevel level);

    // Non-copyable, non-movable
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    Logger(Logger&&) = delete;
    Logger& operator=(Logger&&) = delete;

private:
    Logger() = default;
    ~Logger() = default;

    mutable std::mutex mutex_;
    std::shared_ptr<spdlog::logger> defaultLogger_;
    std::unordered_map<std::string, std::shared_ptr<spdlog::logger>> loggers_;
    LogConfig config_;
    LogLevel globalLevel_ = LogLevel::Info;
    bool initialized_ = false;
};

// Convenience macro for creating a module logger
#define THREATONE_LOGGER(module) \
    static auto& _logger() { \
        static auto logger = ThreatOne::Core::Logger::instance().getModuleLogger(module); \
        return logger; \
    }

} // namespace ThreatOne::Core
