#include "edr/FileMonitor.h"

#include <algorithm>
#include <chrono>

namespace ThreatOne::EDR {

FileMonitor::FileMonitor(size_t ringBufferSize)
    : logger_(Core::Logger::instance().getModuleLogger("FileMonitor"))
    , bufferCapacity_(ringBufferSize) {
    eventBuffer_.resize(bufferCapacity_);
    logger_.info("FileMonitor initialized with buffer size {}", ringBufferSize);
}

void FileMonitor::watchDirectory(const std::filesystem::path& path, bool recursive) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check if already watched
    for (const auto& watch : watches_) {
        if (watch.path == path) {
            logger_.warn("Directory already being watched: {}", path.string());
            return;
        }
    }

    WatchEntry entry;
    entry.path = path;
    entry.recursive = recursive;

    // Initial scan to populate state
    namespace fs = std::filesystem;
    try {
        if (fs::exists(path) && fs::is_directory(path)) {
            if (recursive) {
                for (const auto& dirEntry : fs::recursive_directory_iterator(
                         path, fs::directory_options::skip_permission_denied)) {
                    if (dirEntry.is_regular_file()) {
                        entry.fileStates[dirEntry.path().string()] = dirEntry.last_write_time();
                    }
                }
            } else {
                for (const auto& dirEntry : fs::directory_iterator(
                         path, fs::directory_options::skip_permission_denied)) {
                    if (dirEntry.is_regular_file()) {
                        entry.fileStates[dirEntry.path().string()] = dirEntry.last_write_time();
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        logger_.warn("Error during initial scan of {}: {}", path.string(), e.what());
    }

    watches_.push_back(std::move(entry));
    logger_.info("Watching directory: {} (recursive={})", path.string(), recursive);
}

void FileMonitor::unwatchDirectory(const std::filesystem::path& path) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = std::remove_if(watches_.begin(), watches_.end(),
        [&path](const WatchEntry& entry) { return entry.path == path; });

    if (it != watches_.end()) {
        watches_.erase(it, watches_.end());
        logger_.info("Unwatched directory: {}", path.string());
    }
}

std::vector<FileEvent> FileMonitor::getEvents() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<FileEvent> events;
    events.reserve(bufferCount_);

    for (size_t i = 0; i < bufferCount_; ++i) {
        size_t idx = (bufferHead_ + bufferCapacity_ - bufferCount_ + i) % bufferCapacity_;
        events.push_back(eventBuffer_[idx]);
    }

    return events;
}

void FileMonitor::setCallback(FileEventCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = std::move(callback);
}

void FileMonitor::poll() {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& watch : watches_) {
        scanDirectory(watch);
    }
}

std::vector<SuspiciousFileIndicator> FileMonitor::detectSuspiciousOperations() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<SuspiciousFileIndicator> indicators;
    auto events = std::vector<FileEvent>();
    events.reserve(bufferCount_);
    for (size_t i = 0; i < bufferCount_; ++i) {
        size_t idx = (bufferHead_ + bufferCapacity_ - bufferCount_ + i) % bufferCapacity_;
        events.push_back(eventBuffer_[idx]);
    }

    if (events.empty()) return indicators;

    // Check 1: Mass file creation in temp directories
    int tempCreates = 0;
    std::vector<std::string> tempPaths;
    for (const auto& evt : events) {
        if (evt.action == "create") {
            std::string lpath = evt.path;
            std::transform(lpath.begin(), lpath.end(), lpath.begin(), ::tolower);
            if (lpath.find("/tmp") != std::string::npos ||
                lpath.find("/temp") != std::string::npos ||
                lpath.find("tmp") != std::string::npos) {
                tempCreates++;
                tempPaths.push_back(evt.path);
            }
        }
    }

    if (tempCreates > 10) {
        SuspiciousFileIndicator ind;
        ind.type = "mass_create";
        ind.description = "Mass file creation in temp directory (" + std::to_string(tempCreates) + " files)";
        ind.severity = std::min(1.0, tempCreates / 50.0);
        ind.affectedPaths = tempPaths;
        indicators.push_back(ind);
    }

    // Check 2: Executable file drops
    for (const auto& evt : events) {
        if (evt.action == "create") {
            namespace fs = std::filesystem;
            std::string ext = fs::path(evt.path).extension().string();
            if (ext == ".exe" || ext == ".sh" || ext == ".elf" ||
                ext == ".bin" || ext == ".so" || ext == ".dll") {
                SuspiciousFileIndicator ind;
                ind.type = "executable_drop";
                ind.description = "Executable file created: " + evt.path;
                ind.severity = 0.6;
                ind.affectedPaths = {evt.path};
                indicators.push_back(ind);
            }
        }
    }

    // Check 3: Hidden file creation
    for (const auto& evt : events) {
        if (evt.action == "create") {
            namespace fs = std::filesystem;
            std::string filename = fs::path(evt.path).filename().string();
            if (!filename.empty() && filename[0] == '.' && filename != "." && filename != "..") {
                SuspiciousFileIndicator ind;
                ind.type = "hidden_file";
                ind.description = "Hidden file created: " + evt.path;
                ind.severity = 0.3;
                ind.affectedPaths = {evt.path};
                indicators.push_back(ind);
            }
        }
    }

    return indicators;
}

void FileMonitor::clearEvents() {
    std::lock_guard<std::mutex> lock(mutex_);
    bufferHead_ = 0;
    bufferCount_ = 0;
}

void FileMonitor::scanDirectory(WatchEntry& entry) {
    namespace fs = std::filesystem;

    std::unordered_map<std::string, fs::file_time_type> currentFiles;

    try {
        if (!fs::exists(entry.path) || !fs::is_directory(entry.path)) {
            return;
        }

        if (entry.recursive) {
            for (const auto& dirEntry : fs::recursive_directory_iterator(
                     entry.path, fs::directory_options::skip_permission_denied)) {
                if (dirEntry.is_regular_file()) {
                    currentFiles[dirEntry.path().string()] = dirEntry.last_write_time();
                }
            }
        } else {
            for (const auto& dirEntry : fs::directory_iterator(
                     entry.path, fs::directory_options::skip_permission_denied)) {
                if (dirEntry.is_regular_file()) {
                    currentFiles[dirEntry.path().string()] = dirEntry.last_write_time();
                }
            }
        }
    } catch (const std::exception& e) {
        logger_.warn("Error scanning directory {}: {}", entry.path.string(), e.what());
        return;
    }

    auto now = std::chrono::system_clock::now();
    auto timeStr = std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count());

    // Detect new files (create events)
    for (const auto& [filePath, modTime] : currentFiles) {
        auto it = entry.fileStates.find(filePath);
        if (it == entry.fileStates.end()) {
            // New file
            FileEvent evt;
            evt.path = filePath;
            evt.action = "create";
            evt.timestamp = timeStr;
            addEvent(std::move(evt));
        } else if (it->second != modTime) {
            // Modified file
            FileEvent evt;
            evt.path = filePath;
            evt.action = "modify";
            evt.timestamp = timeStr;
            addEvent(std::move(evt));
        }
    }

    // Detect deleted files
    for (const auto& [filePath, modTime] : entry.fileStates) {
        if (currentFiles.find(filePath) == currentFiles.end()) {
            FileEvent evt;
            evt.path = filePath;
            evt.action = "delete";
            evt.timestamp = timeStr;
            addEvent(std::move(evt));
        }
    }

    // Update state
    entry.fileStates = currentFiles;
}

void FileMonitor::addEvent(FileEvent event) {
    // Notify callback
    if (callback_) {
        callback_(event);
    }

    // Add to ring buffer
    eventBuffer_[bufferHead_] = std::move(event);
    bufferHead_ = (bufferHead_ + 1) % bufferCapacity_;
    if (bufferCount_ < bufferCapacity_) {
        bufferCount_++;
    }
}

} // namespace ThreatOne::EDR
