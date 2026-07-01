#pragma once

// Production-quality stdout color sink for spdlog-compatible logging
// Supports ANSI color codes per log level with thread-safe output

#include "spdlog/spdlog.h"

namespace spdlog {
namespace sinks {

class stdout_color_sink_mt : public sink {
public:
    stdout_color_sink_mt() = default;

    void log(const detail::log_msg& msg) override {
        if (!should_log(msg.lvl)) return;
        std::string formatted = format(msg);
        const char* color = get_color(msg.lvl);
        const char* reset = "\033[0m";

        std::lock_guard<std::mutex> lock(io_mutex_);
        // Error and critical go to stderr, rest to stdout
        std::FILE* target = (msg.lvl >= level::err) ? stderr : stdout;
        std::fprintf(target, "%s%s%s\n", color, formatted.c_str(), reset);
    }

    void flush() override {
        std::lock_guard<std::mutex> lock(io_mutex_);
        std::fflush(stdout);
        std::fflush(stderr);
    }

private:
    static const char* get_color(level lvl) {
        switch (lvl) {
            case level::trace:    return "\033[37m";          // white
            case level::debug:    return "\033[36m";          // cyan
            case level::info:     return "\033[32m";          // green
            case level::warn:     return "\033[33m";          // yellow
            case level::err:      return "\033[31m";          // red
            case level::critical: return "\033[1;31;47m";     // bold red on white bg
            case level::off:      return "";
        }
        return "";
    }

    std::mutex io_mutex_;
};

} // namespace sinks

// Factory function: create a named logger with a stdout color sink
inline std::shared_ptr<logger> stdout_color_mt(const std::string& name) {
    auto sink_ptr = std::make_shared<sinks::stdout_color_sink_mt>();
    auto lg = std::make_shared<logger>(name, std::move(sink_ptr));
    register_logger(lg);
    return lg;
}

} // namespace spdlog
