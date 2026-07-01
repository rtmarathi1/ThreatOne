#pragma once

// ThreatOne Fleet - Remote Manager
// Remote command execution, config push, scan triggers

#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <optional>
#include <mutex>
#include <queue>

#include "core/Logger.h"

namespace ThreatOne::Fleet {

enum class CommandType {
    Scan,
    ConfigPush,
    Restart,
    Update,
    Custom
};

enum class CommandStatus {
    Queued,
    InProgress,
    Completed,
    Failed,
    Cancelled
};

struct CommandResult {
    bool success = false;
    std::string output;
    std::string errorMessage;
    int exitCode = -1;
};

struct RemoteCommand {
    std::string id;
    std::string endpointId;
    CommandType type = CommandType::Custom;
    std::string parameters;
    CommandStatus status = CommandStatus::Queued;
    CommandResult result;
    std::chrono::system_clock::time_point issuedAt;
    std::chrono::system_clock::time_point completedAt;
};

struct ConfigPayload {
    std::string configName;
    std::string configData;
    int version = 1;
};

class IRemoteManager {
public:
    virtual ~IRemoteManager() = default;

    virtual std::string executeCommand(const std::string& endpointId, CommandType type,
                                        const std::string& parameters = "") = 0;
    virtual std::optional<RemoteCommand> getCommandStatus(const std::string& commandId) const = 0;
    virtual bool cancelCommand(const std::string& commandId) = 0;
    virtual std::vector<RemoteCommand> getCommandQueue(const std::string& endpointId) const = 0;
    virtual std::vector<RemoteCommand> getCommandHistory(const std::string& endpointId) const = 0;

    virtual std::string pushConfig(const std::string& endpointId, const ConfigPayload& config) = 0;
    virtual std::string triggerRemoteScan(const std::string& endpointId, const std::string& scanType = "full") = 0;

    // Simulate command completion for testing
    virtual bool completeCommand(const std::string& commandId, const CommandResult& result) = 0;
};

class RemoteManager : public IRemoteManager {
public:
    RemoteManager();
    ~RemoteManager() override = default;

    std::string executeCommand(const std::string& endpointId, CommandType type,
                                const std::string& parameters = "") override;
    std::optional<RemoteCommand> getCommandStatus(const std::string& commandId) const override;
    bool cancelCommand(const std::string& commandId) override;
    std::vector<RemoteCommand> getCommandQueue(const std::string& endpointId) const override;
    std::vector<RemoteCommand> getCommandHistory(const std::string& endpointId) const override;

    std::string pushConfig(const std::string& endpointId, const ConfigPayload& config) override;
    std::string triggerRemoteScan(const std::string& endpointId, const std::string& scanType = "full") override;

    bool completeCommand(const std::string& commandId, const CommandResult& result) override;

private:
    std::string generateId() const;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, RemoteCommand> commands_;
    std::unordered_map<std::string, std::vector<std::string>> endpointCommandQueue_; // endpoint -> command ids
    int nextId_ = 1;
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Fleet
