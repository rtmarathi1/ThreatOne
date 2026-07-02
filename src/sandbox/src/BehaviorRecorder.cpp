#include "sandbox/BehaviorRecorder.h"
#include <optional>
#include <mutex>

#include <algorithm>
#include <chrono>
#include <sstream>

namespace ThreatOne::Sandbox {

BehaviorRecorder::BehaviorRecorder()
    : logger_(Core::Logger::instance().getModuleLogger("BehaviorRecorder")) {
    logger_.info("BehaviorRecorder initialized");
}

std::string BehaviorRecorder::generateId(const std::string& prefix) {
    if (prefix == "SESSION") {
        return "REC-" + std::to_string(nextSessionId_++);
    }
    return "BEH-" + std::to_string(nextBehaviorId_++);
}

std::string BehaviorRecorder::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << time;
    return oss.str();
}

bool BehaviorRecorder::isRecordingEnabled(const std::string& sampleId, BehaviorType type) const {
    auto sessionIt = sampleToSession_.find(sampleId);
    if (sessionIt == sampleToSession_.end()) {
        return true;  // No session means record everything
    }

    auto it = sessions_.find(sessionIt->second);
    if (it == sessions_.end() || !it->second.active) {
        return true;
    }

    const auto& session = it->second;
    switch (type) {
        case BehaviorType::FileOperation:
        case BehaviorType::FileDrop:
            return session.recordFileOps;
        case BehaviorType::RegistryChange:
            return session.recordRegistry;
        case BehaviorType::ProcessCreation:
            return session.recordProcesses;
        case BehaviorType::NetworkConnection:
            return session.recordNetwork;
        default:
            return true;
    }
}

std::string BehaviorRecorder::startRecording(const std::string& sampleId, bool fileOps,
                                              bool registry, bool processes, bool network) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (sampleId.empty()) {
        return "";
    }

    std::string sessionId = generateId("SESSION");

    RecordingSession session;
    session.id = sessionId;
    session.sampleId = sampleId;
    session.active = true;
    session.startedAt = getCurrentTimestamp();
    session.recordFileOps = fileOps;
    session.recordRegistry = registry;
    session.recordProcesses = processes;
    session.recordNetwork = network;

    sessions_[sessionId] = session;
    sampleToSession_[sampleId] = sessionId;
    logger_.info("Started recording session {} for sample {}", sessionId, sampleId);
    return sessionId;
}

bool BehaviorRecorder::stopRecording(const std::string& sessionId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = sessions_.find(sessionId);
    if (it == sessions_.end()) {
        return false;
    }

    if (!it->second.active) {
        return false;
    }

    it->second.active = false;
    it->second.stoppedAt = getCurrentTimestamp();

    auto behavIt = behaviors_.find(it->second.sampleId);
    if (behavIt != behaviors_.end()) {
        it->second.totalBehaviors = behavIt->second.size();
    }

    logger_.info("Stopped recording session {}", sessionId);
    return true;
}

std::optional<RecordingSession> BehaviorRecorder::getSession(const std::string& sessionId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = sessions_.find(sessionId);
    if (it == sessions_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<RecordingSession> BehaviorRecorder::getActiveSessions() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<RecordingSession> active;
    for (const auto& [id, session] : sessions_) {
        if (session.active) {
            active.push_back(session);
        }
    }
    return active;
}

std::string BehaviorRecorder::recordFileOperation(const std::string& sampleId,
                                                   const std::string& action,
                                                   const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!isRecordingEnabled(sampleId, BehaviorType::FileOperation)) {
        return "";
    }

    BehaviorEntry entry;
    entry.id = generateId("BEHAVIOR");
    entry.sampleId = sampleId;
    entry.type = BehaviorType::FileOperation;
    entry.action = action;
    entry.target = path;
    entry.timestamp = getCurrentTimestamp();
    entry.severity = 3;

    behaviors_[sampleId].push_back(entry);
    return entry.id;
}

std::string BehaviorRecorder::recordRegistryChange(const std::string& sampleId,
                                                    const std::string& action,
                                                    const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!isRecordingEnabled(sampleId, BehaviorType::RegistryChange)) {
        return "";
    }

    BehaviorEntry entry;
    entry.id = generateId("BEHAVIOR");
    entry.sampleId = sampleId;
    entry.type = BehaviorType::RegistryChange;
    entry.action = action;
    entry.target = key;
    entry.timestamp = getCurrentTimestamp();
    entry.severity = 5;

    behaviors_[sampleId].push_back(entry);
    return entry.id;
}

std::string BehaviorRecorder::recordProcessCreation(const std::string& sampleId,
                                                     const std::string& processName,
                                                     const std::string& commandLine) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!isRecordingEnabled(sampleId, BehaviorType::ProcessCreation)) {
        return "";
    }

    BehaviorEntry entry;
    entry.id = generateId("BEHAVIOR");
    entry.sampleId = sampleId;
    entry.type = BehaviorType::ProcessCreation;
    entry.action = "create";
    entry.target = processName;
    entry.details = commandLine;
    entry.timestamp = getCurrentTimestamp();
    entry.severity = 6;

    behaviors_[sampleId].push_back(entry);
    return entry.id;
}

std::string BehaviorRecorder::recordNetworkConnection(const std::string& sampleId,
                                                       const std::string& destination,
                                                       int port) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!isRecordingEnabled(sampleId, BehaviorType::NetworkConnection)) {
        return "";
    }

    BehaviorEntry entry;
    entry.id = generateId("BEHAVIOR");
    entry.sampleId = sampleId;
    entry.type = BehaviorType::NetworkConnection;
    entry.action = "connect";
    entry.target = destination + ":" + std::to_string(port);
    entry.timestamp = getCurrentTimestamp();
    entry.severity = 4;

    behaviors_[sampleId].push_back(entry);
    return entry.id;
}

std::string BehaviorRecorder::recordFileDrop(const std::string& sampleId,
                                              const std::string& path,
                                              const std::string& hash) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!isRecordingEnabled(sampleId, BehaviorType::FileDrop)) {
        return "";
    }

    BehaviorEntry entry;
    entry.id = generateId("BEHAVIOR");
    entry.sampleId = sampleId;
    entry.type = BehaviorType::FileDrop;
    entry.action = "drop";
    entry.target = path;
    entry.details = hash;
    entry.timestamp = getCurrentTimestamp();
    entry.severity = 7;

    behaviors_[sampleId].push_back(entry);
    return entry.id;
}

std::vector<BehaviorEntry> BehaviorRecorder::getBehaviors(const std::string& sampleId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = behaviors_.find(sampleId);
    if (it == behaviors_.end()) {
        return {};
    }
    return it->second;
}

std::vector<BehaviorEntry> BehaviorRecorder::getBehaviorsByType(const std::string& sampleId,
                                                                 BehaviorType type) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = behaviors_.find(sampleId);
    if (it == behaviors_.end()) {
        return {};
    }

    std::vector<BehaviorEntry> filtered;
    for (const auto& entry : it->second) {
        if (entry.type == type) {
            filtered.push_back(entry);
        }
    }
    return filtered;
}

uint64_t BehaviorRecorder::getBehaviorCount(const std::string& sampleId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = behaviors_.find(sampleId);
    if (it == behaviors_.end()) {
        return 0;
    }
    return it->second.size();
}

BehaviorReport BehaviorRecorder::generateBehaviorReport(const std::string& sampleId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    BehaviorReport report;
    report.sampleId = sampleId;

    auto it = behaviors_.find(sampleId);
    if (it == behaviors_.end()) {
        return report;
    }

    for (const auto& entry : it->second) {
        switch (entry.type) {
            case BehaviorType::ProcessCreation:
                report.processesCreated.push_back(entry.target);
                break;
            case BehaviorType::FileOperation:
                report.filesModified.push_back(entry.target);
                break;
            case BehaviorType::RegistryChange:
                report.registryChanges.push_back(entry.target);
                break;
            case BehaviorType::NetworkConnection:
                report.networkConnections.push_back(entry.target);
                break;
            case BehaviorType::FileDrop:
                report.droppedFiles.push_back(entry.target);
                break;
            default:
                break;
        }
    }

    return report;
}

uint64_t BehaviorRecorder::getTotalRecordedBehaviors() const {
    std::lock_guard<std::mutex> lock(mutex_);

    uint64_t total = 0;
    for (const auto& [id, entries] : behaviors_) {
        total += entries.size();
    }
    return total;
}

uint64_t BehaviorRecorder::getActiveSessionCount() const {
    std::lock_guard<std::mutex> lock(mutex_);

    uint64_t count = 0;
    for (const auto& [id, session] : sessions_) {
        if (session.active) {
            ++count;
        }
    }
    return count;
}

} // namespace ThreatOne::Sandbox
