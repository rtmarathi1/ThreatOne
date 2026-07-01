#include "core/Config.h"

#include <fstream>
#include <sstream>
#include <cstdlib>
#include <algorithm>

namespace ThreatOne::Core {

Config& Config::instance() {
    static Config instance;
    return instance;
}

Result<void> Config::loadFromFile(const std::filesystem::path& filepath) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!std::filesystem::exists(filepath)) {
        return Result<void>::err(
            Error("Config file not found: " + filepath.string(),
                  ErrorCategory::IO,
                  ErrorSeverity::Error));
    }

    std::ifstream file(filepath);
    if (!file.is_open()) {
        return Result<void>::err(
            Error("Failed to open config file: " + filepath.string(),
                  ErrorCategory::IO,
                  ErrorSeverity::Error));
    }

    std::ostringstream contents;
    contents << file.rdbuf();

    try {
        auto parsed = nlohmann::json::parse(contents.str());
        data_ = parsed;
    } catch (const std::exception& e) {
        return Result<void>::err(
            Error(std::string("Failed to parse config JSON: ") + e.what(),
                  ErrorCategory::Configuration,
                  ErrorSeverity::Error));
    }

    return Result<void>::ok();
}

Result<void> Config::loadFromString(const std::string& jsonString) {
    std::lock_guard<std::mutex> lock(mutex_);

    try {
        auto parsed = nlohmann::json::parse(jsonString);
        data_ = parsed;
    } catch (const std::exception& e) {
        return Result<void>::err(
            Error(std::string("Failed to parse config JSON: ") + e.what(),
                  ErrorCategory::Configuration,
                  ErrorSeverity::Error));
    }

    return Result<void>::ok();
}

Result<void> Config::saveToFile(const std::filesystem::path& filepath) const {
    std::lock_guard<std::mutex> lock(mutex_);

    // Ensure parent directory exists
    auto parentDir = filepath.parent_path();
    if (!parentDir.empty()) {
        std::filesystem::create_directories(parentDir);
    }

    std::ofstream file(filepath);
    if (!file.is_open()) {
        return Result<void>::err(
            Error("Failed to open file for writing: " + filepath.string(),
                  ErrorCategory::IO,
                  ErrorSeverity::Error));
    }

    file << data_.dump(4);
    if (!file.good()) {
        return Result<void>::err(
            Error("Failed to write config file: " + filepath.string(),
                  ErrorCategory::IO,
                  ErrorSeverity::Error));
    }

    return Result<void>::ok();
}

void Config::merge(const nlohmann::json& other) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!other.is_object()) return;

    // Simple recursive merge for objects
    if (data_.is_null()) {
        data_ = nlohmann::json::object();
    }

    for (const auto& [key, val] : other.items()) {
        if (val.is_object() && data_.contains(key) && data_[key].is_object()) {
            // Recursively merge nested objects
            // For simplicity, just overwrite at this level
            for (const auto& [innerKey, innerVal] : val.items()) {
                data_[key][innerKey] = innerVal;
            }
        } else {
            data_[key] = val;
        }
    }
}

std::optional<std::string> Config::getString(const std::string& key) const {
    // Check environment override first
    if (envOverrides_) {
        auto envVal = getEnvOverride(key);
        if (envVal) return envVal;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    const auto* node = resolve(key);
    if (!node || !node->is_string()) return std::nullopt;
    return node->get<std::string>();
}

std::optional<int64_t> Config::getInt(const std::string& key) const {
    // Check environment override first
    if (envOverrides_) {
        auto envVal = getEnvOverride(key);
        if (envVal) {
            try {
                return std::stoll(*envVal);
            } catch (...) {
                // Fall through to JSON lookup
            }
        }
    }

    std::lock_guard<std::mutex> lock(mutex_);
    const auto* node = resolve(key);
    if (!node || !node->is_number_integer()) return std::nullopt;
    return node->get<int64_t>();
}

std::optional<double> Config::getDouble(const std::string& key) const {
    if (envOverrides_) {
        auto envVal = getEnvOverride(key);
        if (envVal) {
            try {
                return std::stod(*envVal);
            } catch (...) {}
        }
    }

    std::lock_guard<std::mutex> lock(mutex_);
    const auto* node = resolve(key);
    if (!node || !node->is_number()) return std::nullopt;
    return node->get<double>();
}

std::optional<bool> Config::getBool(const std::string& key) const {
    if (envOverrides_) {
        auto envVal = getEnvOverride(key);
        if (envVal) {
            if (*envVal == "true" || *envVal == "1" || *envVal == "yes") return true;
            if (*envVal == "false" || *envVal == "0" || *envVal == "no") return false;
        }
    }

    std::lock_guard<std::mutex> lock(mutex_);
    const auto* node = resolve(key);
    if (!node || !node->is_boolean()) return std::nullopt;
    return node->get<bool>();
}

std::optional<nlohmann::json> Config::getJson(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto* node = resolve(key);
    if (!node) return std::nullopt;
    return *node;
}

std::optional<std::vector<std::string>> Config::getStringArray(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto* node = resolve(key);
    if (!node || !node->is_array()) return std::nullopt;

    std::vector<std::string> result;
    for (size_t i = 0; i < node->size(); ++i) {
        const auto& elem = (*node)[i];
        if (elem.is_string()) {
            result.push_back(elem.get<std::string>());
        }
    }
    return result;
}

std::string Config::getString(const std::string& key, const std::string& defaultValue) const {
    auto val = getString(key);
    return val.value_or(defaultValue);
}

int64_t Config::getInt(const std::string& key, int64_t defaultValue) const {
    auto val = getInt(key);
    return val.value_or(defaultValue);
}

double Config::getDouble(const std::string& key, double defaultValue) const {
    auto val = getDouble(key);
    return val.value_or(defaultValue);
}

bool Config::getBool(const std::string& key, bool defaultValue) const {
    auto val = getBool(key);
    return val.value_or(defaultValue);
}

void Config::set(const std::string& key, const nlohmann::json& value) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto* node = resolveOrCreate(key);
        if (node) {
            *node = value;
        }
    }
    notifyChange(key);
}

void Config::setString(const std::string& key, const std::string& value) {
    set(key, nlohmann::json(value));
}

void Config::setInt(const std::string& key, int64_t value) {
    set(key, nlohmann::json(value));
}

void Config::setDouble(const std::string& key, double value) {
    set(key, nlohmann::json(value));
}

void Config::setBool(const std::string& key, bool value) {
    set(key, nlohmann::json(value));
}

bool Config::has(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return resolve(key) != nullptr;
}

void Config::remove(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto parts = splitKey(key);
    if (parts.empty()) return;

    // Navigate to the parent of the key
    nlohmann::json* current = &data_;
    for (size_t i = 0; i < parts.size() - 1; ++i) {
        if (!current->is_object() || !current->contains(parts[i])) return;
        current = &(*current)[parts[i]];
    }

    // Remove the final key
    if (current->is_object() && current->contains(parts.back())) {
        // nlohmann::json doesn't have erase by key in our minimal impl,
        // so we rebuild without the key
        auto& lastKey = parts.back();
        nlohmann::json newObj = nlohmann::json::object();
        for (const auto& [k, v] : current->items()) {
            if (k != lastKey) {
                newObj[k] = v;
            }
        }
        *current = newObj;
    }
}

void Config::enableEnvOverrides(bool enable) {
    envOverrides_ = enable;
}

bool Config::envOverridesEnabled() const {
    return envOverrides_;
}

void Config::onChanged(const std::string& keyPattern, ConfigChangeCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    changeCallbacks_.emplace_back(keyPattern, std::move(callback));
}

const nlohmann::json& Config::raw() const {
    return data_;
}

void Config::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    data_ = nlohmann::json::object();
}

const nlohmann::json* Config::resolve(const std::string& key) const {
    auto parts = splitKey(key);
    const nlohmann::json* current = &data_;

    for (const auto& part : parts) {
        if (!current->is_object() || !current->contains(part)) {
            return nullptr;
        }
        current = &(*current)[part];
    }

    return current;
}

nlohmann::json* Config::resolveOrCreate(const std::string& key) {
    auto parts = splitKey(key);
    if (parts.empty()) return nullptr;

    if (data_.is_null()) {
        data_ = nlohmann::json::object();
    }

    nlohmann::json* current = &data_;

    for (size_t i = 0; i < parts.size() - 1; ++i) {
        if (!current->is_object()) return nullptr;
        if (!current->contains(parts[i])) {
            (*current)[parts[i]] = nlohmann::json::object();
        }
        current = &(*current)[parts[i]];
    }

    if (!current->is_object()) return nullptr;
    // Ensure the final key exists
    if (!current->contains(parts.back())) {
        (*current)[parts.back()] = nlohmann::json();
    }
    return &(*current)[parts.back()];
}

std::vector<std::string> Config::splitKey(const std::string& key) {
    std::vector<std::string> parts;
    std::string current;

    for (char c : key) {
        if (c == '.') {
            if (!current.empty()) {
                parts.push_back(current);
                current.clear();
            }
        } else {
            current += c;
        }
    }

    if (!current.empty()) {
        parts.push_back(current);
    }

    return parts;
}

std::string Config::keyToEnvVar(const std::string& key) {
    std::string envVar = "THREATONE_";
    for (char c : key) {
        if (c == '.') {
            envVar += '_';
        } else {
            envVar += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
    }
    return envVar;
}

std::optional<std::string> Config::getEnvOverride(const std::string& key) const {
    std::string envVar = keyToEnvVar(key);
    const char* val = std::getenv(envVar.c_str());
    if (val) {
        return std::string(val);
    }
    return std::nullopt;
}

void Config::notifyChange(const std::string& key) {
    // Make a copy of callbacks to avoid holding the lock during notifications
    std::vector<std::pair<std::string, ConfigChangeCallback>> callbacks;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        callbacks = changeCallbacks_;
    }

    for (const auto& [pattern, callback] : callbacks) {
        // Simple prefix matching for patterns
        if (key.find(pattern) == 0 || pattern == "*" || pattern == key) {
            callback(key);
        }
    }
}

} // namespace ThreatOne::Core
