#include "edr/RegistryMonitor.h"

#include <fstream>
#include <sstream>
#include <chrono>
#include <algorithm>
#include <functional>

namespace ThreatOne::EDR {

RegistryMonitor::RegistryMonitor(size_t ringBufferSize)
    : logger_(Core::Logger::instance().getModuleLogger("RegistryMonitor"))
    , bufferCapacity_(ringBufferSize) {
    eventBuffer_.resize(bufferCapacity_);
    logger_.info("RegistryMonitor initialized with buffer size {}", ringBufferSize);
}

void RegistryMonitor::watchConfigPath(const std::filesystem::path& path) {
    std::lock_guard<std::mutex> lock(mutex_);

    ConfigFileState state;
    state.path = path;

    namespace fs = std::filesystem;
    try {
        if (fs::exists(path)) {
            state.exists = true;
            state.lastModified = fs::last_write_time(path);
            state.contentHash = computeSimpleHash(path);
        } else {
            state.exists = false;
        }
    } catch (const std::exception& e) {
        logger_.warn("Cannot access config file {}: {}", path.string(), e.what());
        state.exists = false;
    }

    watchedFiles_.push_back(std::move(state));
    logger_.info("Watching config path: {}", path.string());
}

std::vector<RegistryEvent> RegistryMonitor::getEvents() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<RegistryEvent> events;
    events.reserve(bufferCount_);

    for (size_t i = 0; i < bufferCount_; ++i) {
        size_t idx = (bufferHead_ + bufferCapacity_ - bufferCount_ + i) % bufferCapacity_;
        events.push_back(eventBuffer_[idx]);
    }

    return events;
}

std::vector<PersistenceMechanism> RegistryMonitor::detectPersistenceMechanisms() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<PersistenceMechanism> mechanisms;

    // Read events from ring buffer
    for (size_t i = 0; i < bufferCount_; ++i) {
        size_t idx = (bufferHead_ + bufferCapacity_ - bufferCount_ + i) % bufferCapacity_;
        const auto& event = eventBuffer_[idx];
        // Detect cron persistence
        if (event.key.find("crontab") != std::string::npos ||
            event.key.find("cron.d") != std::string::npos) {
            PersistenceMechanism mech;
            mech.type = "cron";
            mech.location = event.key;
            mech.description = "Cron job modification detected";
            mech.severity = "high";
            mechanisms.push_back(mech);
        }

        // Detect ld.so.preload (library injection persistence)
        if (event.key.find("ld.so.preload") != std::string::npos) {
            PersistenceMechanism mech;
            mech.type = "ld_preload";
            mech.location = event.key;
            mech.description = "LD_PRELOAD persistence mechanism detected";
            mech.severity = "critical";
            mechanisms.push_back(mech);
        }

        // Detect systemd unit changes
        if (event.key.find("systemd") != std::string::npos &&
            event.key.find(".service") != std::string::npos) {
            PersistenceMechanism mech;
            mech.type = "systemd";
            mech.location = event.key;
            mech.description = "Systemd service unit modification detected";
            mech.severity = "high";
            mechanisms.push_back(mech);
        }

        // Detect shell profile changes
        if (event.key.find(".bashrc") != std::string::npos ||
            event.key.find(".profile") != std::string::npos ||
            event.key.find(".bash_profile") != std::string::npos ||
            event.key.find("/etc/profile") != std::string::npos) {
            PersistenceMechanism mech;
            mech.type = "shell_profile";
            mech.location = event.key;
            mech.description = "Shell profile modification detected";
            mech.severity = "medium";
            mechanisms.push_back(mech);
        }

        // Detect passwd modifications
        if (event.key.find("/etc/passwd") != std::string::npos) {
            PersistenceMechanism mech;
            mech.type = "passwd";
            mech.location = event.key;
            mech.description = "Password file modification detected";
            mech.severity = "critical";
            mechanisms.push_back(mech);
        }
    }

    return mechanisms;
}

void RegistryMonitor::poll() {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& state : watchedFiles_) {
        checkFile(state);
    }
}

void RegistryMonitor::watchDefaultPaths() {
    // Watch common Linux persistence locations
    static const std::vector<std::string> defaultPaths = {
        "/etc/crontab",
        "/etc/passwd",
        "/etc/ld.so.preload",
        "/etc/profile",
        "/etc/bash.bashrc"
    };

    for (const auto& path : defaultPaths) {
        watchConfigPath(path);
    }
}

void RegistryMonitor::clearEvents() {
    std::lock_guard<std::mutex> lock(mutex_);
    bufferHead_ = 0;
    bufferCount_ = 0;
}

void RegistryMonitor::checkFile(ConfigFileState& state) {
    namespace fs = std::filesystem;

    auto now = std::chrono::system_clock::now();
    auto timeStr = std::to_string(
        std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count());

    try {
        bool currentlyExists = fs::exists(state.path);

        if (!state.exists && currentlyExists) {
            // File was created
            state.exists = true;
            state.lastModified = fs::last_write_time(state.path);
            state.contentHash = computeSimpleHash(state.path);

            RegistryEvent evt;
            evt.key = state.path.string();
            evt.action = "create";
            evt.value = "";
            evt.timestamp = timeStr;
            addEvent(std::move(evt));
        } else if (state.exists && !currentlyExists) {
            // File was deleted
            state.exists = false;

            RegistryEvent evt;
            evt.key = state.path.string();
            evt.action = "delete";
            evt.value = "";
            evt.timestamp = timeStr;
            addEvent(std::move(evt));
        } else if (state.exists && currentlyExists) {
            // Check for modification
            auto currentModTime = fs::last_write_time(state.path);
            if (currentModTime != state.lastModified) {
                std::string newHash = computeSimpleHash(state.path);
                if (newHash != state.contentHash) {
                    state.lastModified = currentModTime;
                    state.contentHash = newHash;

                    RegistryEvent evt;
                    evt.key = state.path.string();
                    evt.action = "modify";
                    evt.value = "";
                    evt.timestamp = timeStr;
                    addEvent(std::move(evt));
                }
            }
        }
    } catch (const std::exception& e) {
        logger_.warn("Error checking config file {}: {}", state.path.string(), e.what());
    }
}

std::string RegistryMonitor::computeSimpleHash(const std::filesystem::path& path) const {
    // Simple hash based on file content (DJB2 hash for quick comparison)
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return "";

    size_t hash = 5381;
    char c;
    while (f.get(c)) {
        hash = ((hash << 5) + hash) + static_cast<unsigned char>(c);
    }

    return std::to_string(hash);
}

void RegistryMonitor::addEvent(RegistryEvent event) {
    // Add to ring buffer
    eventBuffer_[bufferHead_] = std::move(event);
    bufferHead_ = (bufferHead_ + 1) % bufferCapacity_;
    if (bufferCount_ < bufferCapacity_) {
        bufferCount_++;
    }
}

} // namespace ThreatOne::EDR
