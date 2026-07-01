#pragma once

// Production-quality file sinks for spdlog-compatible logging
// Includes: basic_file_sink_mt and rotating_file_sink_mt

#include "spdlog/spdlog.h"

#include <cstdio>
#include <string>

namespace spdlog {
namespace sinks {

// ============================================================================
// Basic file sink - writes all log messages to a single file
// ============================================================================
class basic_file_sink_mt : public sink {
public:
    explicit basic_file_sink_mt(const std::string& filename, bool truncate = false)
        : filename_(filename) {
        const char* mode = truncate ? "w" : "a";
        file_ = std::fopen(filename.c_str(), mode);
    }

    ~basic_file_sink_mt() override {
        if (file_) {
            std::fclose(file_);
        }
    }

    basic_file_sink_mt(const basic_file_sink_mt&) = delete;
    basic_file_sink_mt& operator=(const basic_file_sink_mt&) = delete;

    void log(const detail::log_msg& msg) override {
        if (!should_log(msg.lvl)) return;
        if (!file_) return;
        std::string formatted = format(msg);
        std::lock_guard<std::mutex> lock(io_mutex_);
        std::fprintf(file_, "%s\n", formatted.c_str());
    }

    void flush() override {
        std::lock_guard<std::mutex> lock(io_mutex_);
        if (file_) {
            std::fflush(file_);
        }
    }

private:
    std::string filename_;
    std::FILE* file_{nullptr};
    std::mutex io_mutex_;
};

// ============================================================================
// Rotating file sink - rotates files when they exceed max_size
// Keeps up to max_files rotated copies
// file.log -> file.1.log -> file.2.log -> ... -> file.N.log (deleted)
// ============================================================================
class rotating_file_sink_mt : public sink {
public:
    rotating_file_sink_mt(const std::string& filename,
                          std::size_t max_size,
                          std::size_t max_files)
        : base_filename_(filename)
        , max_size_(max_size)
        , max_files_(max_files)
        , current_size_(0) {
        file_ = std::fopen(filename.c_str(), "a");
        if (file_) {
            std::fseek(file_, 0, SEEK_END);
            current_size_ = static_cast<std::size_t>(std::ftell(file_));
        }
    }

    ~rotating_file_sink_mt() override {
        if (file_) {
            std::fclose(file_);
        }
    }

    rotating_file_sink_mt(const rotating_file_sink_mt&) = delete;
    rotating_file_sink_mt& operator=(const rotating_file_sink_mt&) = delete;

    void log(const detail::log_msg& msg) override {
        if (!should_log(msg.lvl)) return;
        if (!file_) return;
        std::string formatted = format(msg);
        std::lock_guard<std::mutex> lock(io_mutex_);
        std::size_t msg_size = formatted.size() + 1; // +1 for newline
        if (current_size_ + msg_size > max_size_) {
            rotate_();
        }
        std::fprintf(file_, "%s\n", formatted.c_str());
        current_size_ += msg_size;
    }

    void flush() override {
        std::lock_guard<std::mutex> lock(io_mutex_);
        if (file_) {
            std::fflush(file_);
        }
    }

private:
    void rotate_() {
        if (file_) {
            std::fclose(file_);
            file_ = nullptr;
        }

        // Rotate existing files: file.N.log -> deleted, file.(N-1).log -> file.N.log, etc.
        for (std::size_t i = max_files_; i > 0; --i) {
            std::string src = make_filename_(i - 1);
            std::string dst = make_filename_(i);
            // Remove destination if it exists
            std::remove(dst.c_str());
            // Rename source to destination
            std::rename(src.c_str(), dst.c_str());
        }

        // Rename base file to .1
        std::string first_rotated = make_filename_(1);
        std::remove(first_rotated.c_str());
        std::rename(base_filename_.c_str(), first_rotated.c_str());

        // Open a new base file
        file_ = std::fopen(base_filename_.c_str(), "w");
        current_size_ = 0;
    }

    std::string make_filename_(std::size_t index) const {
        if (index == 0) return base_filename_;
        // Insert index before extension: file.log -> file.1.log
        auto dot_pos = base_filename_.rfind('.');
        if (dot_pos == std::string::npos) {
            return base_filename_ + "." + std::to_string(index);
        }
        return base_filename_.substr(0, dot_pos) + "." +
               std::to_string(index) +
               base_filename_.substr(dot_pos);
    }

    std::string base_filename_;
    std::size_t max_size_;
    std::size_t max_files_;
    std::size_t current_size_;
    std::FILE* file_{nullptr};
    std::mutex io_mutex_;
};

} // namespace sinks

// ============================================================================
// Factory functions
// ============================================================================

// Create a named logger with a basic file sink
inline std::shared_ptr<logger> basic_logger_mt(const std::string& name,
                                                const std::string& filename,
                                                bool truncate = false) {
    auto sink_ptr = std::make_shared<sinks::basic_file_sink_mt>(filename, truncate);
    auto lg = std::make_shared<logger>(name, std::move(sink_ptr));
    register_logger(lg);
    return lg;
}

// Create a named logger with a rotating file sink
inline std::shared_ptr<logger> rotating_logger_mt(const std::string& name,
                                                   const std::string& filename,
                                                   std::size_t max_size,
                                                   std::size_t max_files) {
    auto sink_ptr = std::make_shared<sinks::rotating_file_sink_mt>(filename, max_size, max_files);
    auto lg = std::make_shared<logger>(name, std::move(sink_ptr));
    register_logger(lg);
    return lg;
}

} // namespace spdlog
