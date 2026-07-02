#pragma once

// ThreatOne Core - Base Event class and common event types

#include <string>
#include <chrono>
#include <any>
#include <typeindex>
#include <atomic>
#include <unordered_map>

#include "core/Types.h"
#include <stdexcept>
#include <utility>

namespace ThreatOne::Core {

// Event priority for ordering
enum class EventPriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3
};

// Base event class - all events derive from this
class Event {
public:
    Event() : id_(nextId()), timestamp_(SystemClock::now()) {}
    virtual ~Event() = default;

    // Non-copyable but movable
    Event(const Event&) = default;
    Event& operator=(const Event&) = default;
    Event(Event&&) = default;
    Event& operator=(Event&&) = default;

    // Event metadata
    [[nodiscard]] u64 id() const noexcept { return id_; }
    [[nodiscard]] SystemTimePoint timestamp() const noexcept { return timestamp_; }
    [[nodiscard]] virtual std::string eventType() const = 0;
    [[nodiscard]] virtual EventPriority priority() const { return EventPriority::Normal; }

    // Event propagation control
    void stopPropagation() noexcept { propagationStopped_ = true; }
    [[nodiscard]] bool isPropagationStopped() const noexcept { return propagationStopped_; }

    // Optional payload data
    void setData(const std::string& key, std::any value) {
        data_[key] = std::move(value);
    }

    template<typename T>
    [[nodiscard]] T getData(const std::string& key) const {
        auto it = data_.find(key);
        if (it == data_.end()) {
            throw std::runtime_error("Event data key not found: " + key);
        }
        return std::any_cast<T>(it->second);
    }

    [[nodiscard]] bool hasData(const std::string& key) const {
        return data_.find(key) != data_.end();
    }

private:
    static u64 nextId() {
        static std::atomic<u64> counter{0};
        return ++counter;
    }

    u64 id_;
    SystemTimePoint timestamp_;
    bool propagationStopped_ = false;
    std::unordered_map<std::string, std::any> data_;
};

// System lifecycle events
class SystemEvent : public Event {
public:
    enum class Type {
        Starting,
        Started,
        Stopping,
        Stopped,
        ConfigChanged,
        Error,
        Warning
    };

    explicit SystemEvent(Type type, std::string message = "")
        : type_(type), message_(std::move(message)) {}

    [[nodiscard]] std::string eventType() const override { return "SystemEvent"; }
    [[nodiscard]] Type systemType() const noexcept { return type_; }
    [[nodiscard]] const std::string& message() const noexcept { return message_; }

    [[nodiscard]] EventPriority priority() const override {
        switch (type_) {
            case Type::Error:    return EventPriority::High;
            case Type::Stopping: return EventPriority::High;
            case Type::Warning:  return EventPriority::Normal;
            default:             return EventPriority::Normal;
        }
    }

private:
    Type type_;
    std::string message_;
};

// Security-related events
class SecurityEvent : public Event {
public:
    enum class Type {
        ThreatDetected,
        ThreatBlocked,
        ThreatCleared,
        ScanStarted,
        ScanCompleted,
        PolicyViolation,
        AuthFailure,
        Intrusion,
        Anomaly
    };

    enum class Severity {
        Info,
        Low,
        Medium,
        High,
        Critical
    };

    SecurityEvent(Type type, Severity severity, std::string description)
        : type_(type)
        , severity_(severity)
        , description_(std::move(description)) {}

    [[nodiscard]] std::string eventType() const override { return "SecurityEvent"; }
    [[nodiscard]] Type securityType() const noexcept { return type_; }
    [[nodiscard]] Severity severity() const noexcept { return severity_; }
    [[nodiscard]] const std::string& description() const noexcept { return description_; }

    [[nodiscard]] EventPriority priority() const override {
        switch (severity_) {
            case Severity::Critical: return EventPriority::Critical;
            case Severity::High:     return EventPriority::High;
            case Severity::Medium:   return EventPriority::Normal;
            default:                 return EventPriority::Low;
        }
    }

    void setSource(std::string source) { source_ = std::move(source); }
    [[nodiscard]] const std::string& source() const noexcept { return source_; }

private:
    Type type_;
    Severity severity_;
    std::string description_;
    std::string source_;
};

// UI-related events (for decoupled UI updates)
class UIEvent : public Event {
public:
    enum class Type {
        NavigationChanged,
        ThemeChanged,
        NotificationAdded,
        DialogRequested,
        ProgressUpdate,
        ViewRefresh
    };

    explicit UIEvent(Type type, std::string detail = "")
        : type_(type), detail_(std::move(detail)) {}

    [[nodiscard]] std::string eventType() const override { return "UIEvent"; }
    [[nodiscard]] Type uiType() const noexcept { return type_; }
    [[nodiscard]] const std::string& detail() const noexcept { return detail_; }

private:
    Type type_;
    std::string detail_;
};

// Plugin lifecycle events
class PluginEvent : public Event {
public:
    enum class Type {
        Loading,
        Loaded,
        Initializing,
        Initialized,
        Unloading,
        Unloaded,
        Error
    };

    PluginEvent(Type type, std::string pluginName)
        : type_(type), pluginName_(std::move(pluginName)) {}

    [[nodiscard]] std::string eventType() const override { return "PluginEvent"; }
    [[nodiscard]] Type pluginType() const noexcept { return type_; }
    [[nodiscard]] const std::string& pluginName() const noexcept { return pluginName_; }

private:
    Type type_;
    std::string pluginName_;
};

// Data/database events
class DataEvent : public Event {
public:
    enum class Type {
        Connected,
        Disconnected,
        MigrationStarted,
        MigrationCompleted,
        QueryError,
        DataChanged
    };

    explicit DataEvent(Type type, std::string detail = "")
        : type_(type), detail_(std::move(detail)) {}

    [[nodiscard]] std::string eventType() const override { return "DataEvent"; }
    [[nodiscard]] Type dataType() const noexcept { return type_; }
    [[nodiscard]] const std::string& detail() const noexcept { return detail_; }

private:
    Type type_;
    std::string detail_;
};

} // namespace ThreatOne::Core
