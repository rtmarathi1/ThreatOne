#pragma once

// ThreatOne Core - Configuration Manager
// JSON-based hierarchical configuration with dot notation access,
// typed getters, defaults, and environment variable overrides.

#include <string>
#include <string_view>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>
#include <functional>
#include <filesystem>

#include <nlohmann/json.hpp>
#include "core/Error.h"
#include <cstdint>
#include <utility>

namespace ThreatOne::Core {

// Callback for config change notifications
using ConfigChangeCallback = std::function<void(const std::string& key)>;

class Config {
public:
    // Singleton access
    static Config& instance();

    // Load configuration from a JSON file
    Result<void> loadFromFile(const std::filesystem::path& filepath);

    // Load configuration from a JSON string
    Result<void> loadFromString(const std::string& jsonString);

    // Save current configuration to a file
    Result<void> saveToFile(const std::filesystem::path& filepath) const;

    // Merge another config on top (values in other override existing)
    void merge(const nlohmann::json& other);

    // Get values with dot notation (e.g., "database.host")
    [[nodiscard]] std::optional<std::string> getString(const std::string& key) const;
    [[nodiscard]] std::optional<int64_t> getInt(const std::string& key) const;
    [[nodiscard]] std::optional<double> getDouble(const std::string& key) const;
    [[nodiscard]] std::optional<bool> getBool(const std::string& key) const;
    [[nodiscard]] std::optional<nlohmann::json> getJson(const std::string& key) const;
    [[nodiscard]] std::optional<std::vector<std::string>> getStringArray(const std::string& key) const;

    // Get values with default fallback
    [[nodiscard]] std::string getString(const std::string& key, const std::string& defaultValue) const;
    [[nodiscard]] int64_t getInt(const std::string& key, int64_t defaultValue) const;
    [[nodiscard]] double getDouble(const std::string& key, double defaultValue) const;
    [[nodiscard]] bool getBool(const std::string& key, bool defaultValue) const;

    // Set values with dot notation
    void set(const std::string& key, const nlohmann::json& value);
    void setString(const std::string& key, const std::string& value);
    void setInt(const std::string& key, int64_t value);
    void setDouble(const std::string& key, double value);
    void setBool(const std::string& key, bool value);

    // Check if key exists
    [[nodiscard]] bool has(const std::string& key) const;

    // Remove a key
    void remove(const std::string& key);

    // Environment variable override support
    // Keys are mapped: "database.host" -> THREATONE_DATABASE_HOST
    void enableEnvOverrides(bool enable = true);
    [[nodiscard]] bool envOverridesEnabled() const;

    // Config change notification
    void onChanged(const std::string& keyPattern, ConfigChangeCallback callback);

    // Access raw JSON (read-only)
    [[nodiscard]] const nlohmann::json& raw() const;

    // Reset to empty
    void clear();

    // Non-copyable, non-movable
    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;
    Config(Config&&) = delete;
    Config& operator=(Config&&) = delete;

private:
    Config() = default;
    ~Config() = default;

    // Navigate to a nested key using dot notation, returns nullptr if not found
    [[nodiscard]] const nlohmann::json* resolve(const std::string& key) const;
    nlohmann::json* resolveOrCreate(const std::string& key);

    // Split dot-separated key into components
    [[nodiscard]] static std::vector<std::string> splitKey(const std::string& key);

    // Convert key to environment variable name
    [[nodiscard]] static std::string keyToEnvVar(const std::string& key);

    // Try to get value from environment variable override
    [[nodiscard]] std::optional<std::string> getEnvOverride(const std::string& key) const;

    // Notify change listeners
    void notifyChange(const std::string& key);

    mutable std::mutex mutex_;
    nlohmann::json data_;
    bool envOverrides_ = false;
    std::vector<std::pair<std::string, ConfigChangeCallback>> changeCallbacks_;
};

} // namespace ThreatOne::Core
