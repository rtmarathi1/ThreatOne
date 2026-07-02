// ThreatOne Database - Base Model common utility implementations
// Most Model logic is in the template header (Model.h).
// This file provides any non-template support functions.

#include <database/Model.h>
#include <chrono>
#include <string>

namespace ThreatOne::Database {

// The Model<T> class is fully header-implemented via CRTP templates.
// This translation unit ensures the library has at least one non-template
// symbol from the model infrastructure and can be linked properly.

// Helper: Generate a timestamp string for "now" in ISO 8601 format
std::string currentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&time));
    return std::string(buf);
}

} // namespace ThreatOne::Database
