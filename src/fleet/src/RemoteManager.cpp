#include "fleet/RemoteManager.h"

#include <algorithm>
#include <sstream>
#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace ThreatOne::Fleet {

RemoteManager::RemoteManager()
    : logger_("RemoteManager") {
    logger_.info("Remote Manager initialized");
}

std::string RemoteManager::generateId() const {
    std::ostringstream oss;
    oss << "cmd-" << nextId_;
    return oss.str();
}

std::string RemoteManager::executeCommand(const std::string& endpointId, CommandType type,
                                            const std::string& parameters) {
    std::lock_guard<std::mutex> lock(mutex_);

    RemoteCommand cmd;
    cmd.id = generateId();
    ++nextId_;
    cmd.endpointId = endpointId;
    cmd.type = type;
    cmd.parameters = parameters;
    cmd.status = CommandStatus::Queued;
    cmd.issuedAt = std::chrono::system_clock::now();

    commands_[cmd.id] = cmd;
    endpointCommandQueue_[endpointId].push_back(cmd.id);

    logger_.info("Queued command {} for endpoint {}", cmd.id, endpointId);
    return cmd.id;
}

std::optional<RemoteCommand> RemoteManager::getCommandStatus(const std::string& commandId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = commands_.find(commandId);
    if (it == commands_.end()) {
        return std::nullopt;
    }
    return it->second;
}

bool RemoteManager::cancelCommand(const std::string& commandId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = commands_.find(commandId);
    if (it == commands_.end()) {
        return false;
    }

    // Can only cancel queued or in-progress commands
    if (it->second.status != CommandStatus::Queued &&
        it->second.status != CommandStatus::InProgress) {
        return false;
    }

    it->second.status = CommandStatus::Cancelled;
    it->second.completedAt = std::chrono::system_clock::now();
    logger_.info("Cancelled command: {}", commandId);
    return true;
}

std::vector<RemoteCommand> RemoteManager::getCommandQueue(const std::string& endpointId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<RemoteCommand> result;
    auto it = endpointCommandQueue_.find(endpointId);
    if (it == endpointCommandQueue_.end()) {
        return result;
    }

    for (const auto& cmdId : it->second) {
        auto cmdIt = commands_.find(cmdId);
        if (cmdIt != commands_.end() && cmdIt->second.status == CommandStatus::Queued) {
            result.push_back(cmdIt->second);
        }
    }
    return result;
}

std::vector<RemoteCommand> RemoteManager::getCommandHistory(const std::string& endpointId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<RemoteCommand> result;
    auto it = endpointCommandQueue_.find(endpointId);
    if (it == endpointCommandQueue_.end()) {
        return result;
    }

    for (const auto& cmdId : it->second) {
        auto cmdIt = commands_.find(cmdId);
        if (cmdIt != commands_.end()) {
            result.push_back(cmdIt->second);
        }
    }
    return result;
}

std::string RemoteManager::pushConfig(const std::string& endpointId, const ConfigPayload& config) {
    std::string params = "config:" + config.configName + ";version:" + std::to_string(config.version) +
                         ";data:" + config.configData;
    return executeCommand(endpointId, CommandType::ConfigPush, params);
}

std::string RemoteManager::triggerRemoteScan(const std::string& endpointId, const std::string& scanType) {
    return executeCommand(endpointId, CommandType::Scan, "type:" + scanType);
}

bool RemoteManager::completeCommand(const std::string& commandId, const CommandResult& result) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = commands_.find(commandId);
    if (it == commands_.end()) {
        return false;
    }

    if (it->second.status == CommandStatus::Cancelled ||
        it->second.status == CommandStatus::Completed ||
        it->second.status == CommandStatus::Failed) {
        return false;
    }

    it->second.result = result;
    it->second.status = result.success ? CommandStatus::Completed : CommandStatus::Failed;
    it->second.completedAt = std::chrono::system_clock::now();
    return true;
}

} // namespace ThreatOne::Fleet
