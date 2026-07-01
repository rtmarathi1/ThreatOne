#pragma once

// Simplified basic_file_sink stub for spdlog compatibility

#include "spdlog/spdlog.h"
#include <fstream>

namespace spdlog {
namespace sinks {

class basic_file_sink_mt {
public:
    explicit basic_file_sink_mt(const std::string& /*filename*/, bool /*truncate*/ = false) {}
};

} // namespace sinks

inline std::shared_ptr<logger> basic_logger_mt(const std::string& name,
                                                const std::string& /*filename*/,
                                                bool /*truncate*/ = false) {
    return std::make_shared<logger>(name);
}

} // namespace spdlog
