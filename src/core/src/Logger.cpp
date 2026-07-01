#include "core/Logger.h"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <filesystem>

namespace ThreatOne::Core {

// ModuleLogger implementation
ModuleLogger::ModuleLogger(std::string moduleName)
    : moduleName_(std::move(moduleName))
    , logger_(spdlog::get(moduleName_)) {
    if (!logger_) {
        logger_ = std::make_shared<spdlog::logger>(moduleName_);
    }
}

void ModuleLogger::setLevel(LogLevel level) {
    if (logger_) {
        logger_->set_level(Logger::toSpdlogLevel(level));
    }
}

LogLevel ModuleLogger::getLevel() const {
    if (!logger_) return LogLevel::Off;
    switch (logger_->get_level()) {
        case spdlog::level::trace:    return LogLevel::Trace;
        case spdlog::level::debug:    return LogLevel::Debug;
        case spdlog::level::info:     return LogLevel::Info;
        case spdlog::level::warn:     return LogLevel::Warn;
        case spdlog::level::err:      return LogLevel::Error;
        case spdlog::level::critical: return LogLevel::Critical;
        case spdlog::level::off:      return LogLevel::Off;
    }
    return LogLevel::Info;
}

// Logger singleton implementation
Logger& Logger::instance() {
    static Logger instance;
    return instance;
}

void Logger::initialize(const LogConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Re-entry guard: if already initialized, this is a no-op.
    // This allows main() to pre-configure the logger before Application::initialize()
    // calls initLogger() without the second call overwriting the configuration.
    if (initialized_) return;

    config_ = config;
    globalLevel_ = config.consoleLevel;

    // Create default logger
    defaultLogger_ = std::make_shared<spdlog::logger>("ThreatOne");
    defaultLogger_->set_level(toSpdlogLevel(globalLevel_));

    // Create log directory if file logging is enabled
    if (config_.enableFile) {
        std::filesystem::create_directories(config_.logDirectory);
    }

    initialized_ = true;
}

void Logger::shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    loggers_.clear();
    defaultLogger_.reset();
    initialized_ = false;
}

ModuleLogger Logger::getModuleLogger(const std::string& moduleName) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = loggers_.find(moduleName);
    if (it == loggers_.end()) {
        auto logger = std::make_shared<spdlog::logger>(moduleName);
        logger->set_level(toSpdlogLevel(globalLevel_));
        loggers_[moduleName] = logger;
    }

    return ModuleLogger(moduleName);
}

void Logger::setGlobalLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    globalLevel_ = level;

    auto spdLevel = toSpdlogLevel(level);
    if (defaultLogger_) {
        defaultLogger_->set_level(spdLevel);
    }
    for (auto& [name, logger] : loggers_) {
        logger->set_level(spdLevel);
    }
}

LogLevel Logger::getGlobalLevel() const {
    return globalLevel_;
}

void Logger::setModuleLevel(const std::string& moduleName, LogLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = loggers_.find(moduleName);
    if (it != loggers_.end()) {
        it->second->set_level(toSpdlogLevel(level));
    }
}

spdlog::level Logger::toSpdlogLevel(LogLevel level) {
    switch (level) {
        case LogLevel::Trace:    return spdlog::level::trace;
        case LogLevel::Debug:    return spdlog::level::debug;
        case LogLevel::Info:     return spdlog::level::info;
        case LogLevel::Warn:     return spdlog::level::warn;
        case LogLevel::Error:    return spdlog::level::err;
        case LogLevel::Critical: return spdlog::level::critical;
        case LogLevel::Off:      return spdlog::level::off;
    }
    return spdlog::level::info;
}

} // namespace ThreatOne::Core
