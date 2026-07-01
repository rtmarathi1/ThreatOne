#pragma once

#include <string>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace ThreatOne::Utils {

class TimeUtils {
public:
    static std::string now() {
        auto tp = std::chrono::system_clock::now();
        return format(tp);
    }

    static std::string format(const std::chrono::system_clock::time_point& tp,
                              const std::string& fmt = "%Y-%m-%d %H:%M:%S") {
        auto time = std::chrono::system_clock::to_time_t(tp);
        std::tm tm{};
#if defined(_WIN32)
        localtime_s(&tm, &time);
#else
        localtime_r(&time, &tm);
#endif
        std::ostringstream ss;
        ss << std::put_time(&tm, fmt.c_str());
        return ss.str();
    }

    static std::chrono::system_clock::time_point parse(const std::string& str,
                                                        const std::string& fmt = "%Y-%m-%d %H:%M:%S") {
        std::tm tm{};
        std::istringstream ss(str);
        ss >> std::get_time(&tm, fmt.c_str());
        return std::chrono::system_clock::from_time_t(std::mktime(&tm));
    }

    static double elapsed(const std::chrono::steady_clock::time_point& start) {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration<double>(now - start).count();
    }
};

class Timer {
public:
    Timer() : start_(std::chrono::steady_clock::now()) {}

    void reset() {
        start_ = std::chrono::steady_clock::now();
    }

    [[nodiscard]] double elapsedSeconds() const {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration<double>(now - start_).count();
    }

    [[nodiscard]] double elapsedMilliseconds() const {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration<double, std::milli>(now - start_).count();
    }

    [[nodiscard]] int64_t elapsedMicroseconds() const {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::microseconds>(now - start_).count();
    }

private:
    std::chrono::steady_clock::time_point start_;
};

} // namespace ThreatOne::Utils
