#pragma once

// ThreatOne Scanner - Signature Database
// In-memory store of threat signatures with O(1) hash lookup

#include <string>
#include <vector>
#include <optional>
#include <unordered_map>
#include <mutex>
#include <cstdint>
#include <filesystem>

#include <core/Error.h>
#include <nlohmann/json.hpp>

namespace ThreatOne::Scanner {

// Threat severity levels for signatures
enum class ThreatLevel {
    Low,
    Medium,
    High,
    Critical
};

// Convert ThreatLevel to/from string
std::string threatLevelToString(ThreatLevel level);
ThreatLevel threatLevelFromString(const std::string& str);

// A single threat signature record
struct Signature {
    uint64_t id = 0;
    std::string name;
    std::string hash;         // SHA256 hash to match against
    ThreatLevel threatLevel = ThreatLevel::Medium;
    std::string category;
    std::string description;
    std::string dateAdded;
};

// In-memory signature database with CRUD operations
class SignatureDatabase {
public:
    SignatureDatabase() = default;

    // CRUD operations
    Core::Result<void, Core::Error> addSignature(const Signature& sig);
    Core::Result<void, Core::Error> removeSignature(uint64_t id);
    Core::Result<void, Core::Error> updateSignature(const Signature& sig);
    Core::Result<Signature, Core::Error> getSignature(uint64_t id) const;

    // Lookup by hash (O(1) via unordered_map)
    std::optional<Signature> lookupByHash(const std::string& hash) const;

    // Load signatures from JSON file
    Core::Result<size_t, Core::Error> loadFromJson(const std::filesystem::path& filePath);

    // Load signatures from JSON string
    Core::Result<size_t, Core::Error> loadFromJsonString(const std::string& jsonStr);

    // Get all signatures
    std::vector<Signature> getAllSignatures() const;

    // Get signature count
    size_t size() const;

    // Clear all signatures
    void clear();

private:
    Core::Result<size_t, Core::Error> parseAndLoad(const nlohmann::json& j);

    mutable std::mutex mutex_;
    std::unordered_map<uint64_t, Signature> signatures_;  // id -> signature
    std::unordered_map<std::string, uint64_t> hashIndex_; // hash -> id (for O(1) lookup)
    uint64_t nextId_ = 1;
};

} // namespace ThreatOne::Scanner
