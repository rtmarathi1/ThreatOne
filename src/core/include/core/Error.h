#pragma once

// ThreatOne Core - Error handling: Result<T,E> type, error categories, exception hierarchy

#include <string>
#include <string_view>
#include <variant>
#include <stdexcept>
#include <utility>
#include <type_traits>
#include <source_location>

namespace ThreatOne::Core {

// Error categories for classification
enum class ErrorCategory {
    None = 0,
    System,         // OS-level errors
    IO,             // File/network I/O errors
    Configuration,  // Config parsing/validation errors
    Plugin,         // Plugin loading/initialization errors
    Security,       // Security-related errors
    Database,       // Database operation errors
    Network,        // Network communication errors
    Validation,     // Input validation errors
    Internal,       // Internal logic errors
    Unknown         // Unclassified errors
};

// Error severity levels
enum class ErrorSeverity {
    Warning,    // Non-fatal, operation may continue
    Error,      // Operation failed but system is stable
    Critical,   // System stability may be compromised
    Fatal       // System must shut down
};

// Structured error information
class Error {
public:
    Error() = default;

    explicit Error(std::string message,
                   ErrorCategory category = ErrorCategory::Unknown,
                   ErrorSeverity severity = ErrorSeverity::Error)
        : message_(std::move(message))
        , category_(category)
        , severity_(severity) {}

    Error(std::string message,
          ErrorCategory category,
          ErrorSeverity severity,
          std::string context)
        : message_(std::move(message))
        , category_(category)
        , severity_(severity)
        , context_(std::move(context)) {}

    // Accessors
    [[nodiscard]] const std::string& message() const noexcept { return message_; }
    [[nodiscard]] ErrorCategory category() const noexcept { return category_; }
    [[nodiscard]] ErrorSeverity severity() const noexcept { return severity_; }
    [[nodiscard]] const std::string& context() const noexcept { return context_; }

    // Builder pattern for adding context
    Error& withContext(std::string ctx) {
        context_ = std::move(ctx);
        return *this;
    }

    Error& withCategory(ErrorCategory cat) {
        category_ = cat;
        return *this;
    }

    Error& withSeverity(ErrorSeverity sev) {
        severity_ = sev;
        return *this;
    }

    // String representation
    [[nodiscard]] std::string toString() const {
        std::string result = "[" + categoryToString() + "] " + message_;
        if (!context_.empty()) {
            result += " (context: " + context_ + ")";
        }
        return result;
    }

    explicit operator bool() const noexcept {
        return !message_.empty();
    }

private:
    [[nodiscard]] std::string categoryToString() const {
        switch (category_) {
            case ErrorCategory::None:          return "None";
            case ErrorCategory::System:        return "System";
            case ErrorCategory::IO:            return "IO";
            case ErrorCategory::Configuration: return "Configuration";
            case ErrorCategory::Plugin:        return "Plugin";
            case ErrorCategory::Security:      return "Security";
            case ErrorCategory::Database:      return "Database";
            case ErrorCategory::Network:       return "Network";
            case ErrorCategory::Validation:    return "Validation";
            case ErrorCategory::Internal:      return "Internal";
            case ErrorCategory::Unknown:       return "Unknown";
        }
        return "Unknown";
    }

    std::string message_;
    ErrorCategory category_ = ErrorCategory::None;
    ErrorSeverity severity_ = ErrorSeverity::Error;
    std::string context_;
};

// Result<T, E> type - inspired by Rust's Result
// Uses std::variant internally for value-or-error semantics
template<typename T, typename E = Error>
class Result {
public:
    // Success constructors
    Result(const T& value) : storage_(value) {} // NOLINT(google-explicit-constructor)
    Result(T&& value) : storage_(std::move(value)) {} // NOLINT(google-explicit-constructor)

    // Error constructor (tag-based to avoid ambiguity)
    struct ErrorTag {};
    Result(ErrorTag, const E& error) : storage_(error) {}
    Result(ErrorTag, E&& error) : storage_(std::move(error)) {}

    // Factory methods
    static Result ok(T value) {
        return Result(std::move(value));
    }

    static Result err(E error) {
        return Result(ErrorTag{}, std::move(error));
    }

    // State checks
    [[nodiscard]] bool isOk() const noexcept {
        return std::holds_alternative<T>(storage_);
    }

    [[nodiscard]] bool isErr() const noexcept {
        return std::holds_alternative<E>(storage_);
    }

    explicit operator bool() const noexcept {
        return isOk();
    }

    // Value access (throws if error)
    [[nodiscard]] T& value() & {
        if (isErr()) {
            throw std::runtime_error("Result::value() called on error result");
        }
        return std::get<T>(storage_);
    }

    [[nodiscard]] const T& value() const& {
        if (isErr()) {
            throw std::runtime_error("Result::value() called on error result");
        }
        return std::get<T>(storage_);
    }

    [[nodiscard]] T&& value() && {
        if (isErr()) {
            throw std::runtime_error("Result::value() called on error result");
        }
        return std::get<T>(std::move(storage_));
    }

    // Error access (throws if ok)
    [[nodiscard]] E& error() & {
        if (isOk()) {
            throw std::runtime_error("Result::error() called on ok result");
        }
        return std::get<E>(storage_);
    }

    [[nodiscard]] const E& error() const& {
        if (isOk()) {
            throw std::runtime_error("Result::error() called on ok result");
        }
        return std::get<E>(storage_);
    }

    // Value or default
    [[nodiscard]] T valueOr(T defaultValue) const& {
        if (isOk()) return std::get<T>(storage_);
        return defaultValue;
    }

    [[nodiscard]] T valueOr(T defaultValue) && {
        if (isOk()) return std::get<T>(std::move(storage_));
        return defaultValue;
    }

    // Monadic operations
    template<typename F>
    auto map(F&& f) const -> Result<decltype(f(std::declval<T>())), E> {
        using U = decltype(f(std::declval<T>()));
        if (isOk()) {
            return Result<U, E>::ok(f(std::get<T>(storage_)));
        }
        return Result<U, E>::err(std::get<E>(storage_));
    }

    template<typename F>
    auto andThen(F&& f) const -> decltype(f(std::declval<T>())) {
        if (isOk()) {
            return f(std::get<T>(storage_));
        }
        using ReturnType = decltype(f(std::declval<T>()));
        return ReturnType::err(std::get<E>(storage_));
    }

private:
    std::variant<T, E> storage_;
};

// Specialization for void success type
template<typename E>
class Result<void, E> {
public:
    Result() : hasError_(false) {}

    struct ErrorTag {};
    Result(ErrorTag, const E& error) : error_(error), hasError_(true) {}
    Result(ErrorTag, E&& error) : error_(std::move(error)), hasError_(true) {}

    static Result ok() { return Result(); }
    static Result err(E error) { return Result(ErrorTag{}, std::move(error)); }

    [[nodiscard]] bool isOk() const noexcept { return !hasError_; }
    [[nodiscard]] bool isErr() const noexcept { return hasError_; }
    explicit operator bool() const noexcept { return isOk(); }

    [[nodiscard]] E& error() & {
        if (!hasError_) throw std::runtime_error("Result::error() called on ok result");
        return error_;
    }

    [[nodiscard]] const E& error() const& {
        if (!hasError_) throw std::runtime_error("Result::error() called on ok result");
        return error_;
    }

private:
    E error_;
    bool hasError_;
};

// Convenience factory functions
template<typename T>
Result<T> makeOk(T value) {
    return Result<T>::ok(std::move(value));
}

template<typename T = void>
Result<T> makeErr(Error error) {
    return Result<T>::err(std::move(error));
}

inline Error makeError(std::string message,
                       ErrorCategory category = ErrorCategory::Unknown,
                       ErrorSeverity severity = ErrorSeverity::Error) {
    return Error(std::move(message), category, severity);
}

// Exception hierarchy
class ThreatOneException : public std::runtime_error {
public:
    explicit ThreatOneException(const std::string& message,
                                 ErrorCategory category = ErrorCategory::Unknown)
        : std::runtime_error(message)
        , category_(category) {}

    [[nodiscard]] ErrorCategory category() const noexcept { return category_; }

private:
    ErrorCategory category_;
};

class ConfigException : public ThreatOneException {
public:
    explicit ConfigException(const std::string& message)
        : ThreatOneException(message, ErrorCategory::Configuration) {}
};

class PluginException : public ThreatOneException {
public:
    explicit PluginException(const std::string& message)
        : ThreatOneException(message, ErrorCategory::Plugin) {}
};

class IOError : public ThreatOneException {
public:
    explicit IOError(const std::string& message)
        : ThreatOneException(message, ErrorCategory::IO) {}
};

class SecurityException : public ThreatOneException {
public:
    explicit SecurityException(const std::string& message)
        : ThreatOneException(message, ErrorCategory::Security) {}
};

class DatabaseException : public ThreatOneException {
public:
    explicit DatabaseException(const std::string& message)
        : ThreatOneException(message, ErrorCategory::Database) {}
};

} // namespace ThreatOne::Core
