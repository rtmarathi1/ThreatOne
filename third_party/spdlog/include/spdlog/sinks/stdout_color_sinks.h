#pragma once

// Simplified stdout_color_sinks stub for spdlog compatibility

#include "spdlog/spdlog.h"

namespace spdlog {
namespace sinks {

class stdout_color_sink_mt {
public:
    stdout_color_sink_mt() = default;
};

} // namespace sinks

namespace stdout_color_mt_detail {

inline std::shared_ptr<logger> create(const std::string& name) {
    return std::make_shared<logger>(name);
}

} // namespace stdout_color_mt_detail

inline std::shared_ptr<logger> stdout_color_mt(const std::string& name) {
    return std::make_shared<logger>(name);
}

} // namespace spdlog
