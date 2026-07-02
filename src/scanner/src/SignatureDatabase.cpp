#include "scanner/SignatureDatabase.h"

#include <fstream>
#include <iterator>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace ThreatOne::Scanner {

std::string threatLevelToString(ThreatLevel level) {
    switch (level) {
        case ThreatLevel::Low:      return "low";
        case ThreatLevel::Medium:   return "medium";
        case ThreatLevel::High:     return "high";
        case ThreatLevel::Critical: return "critical";
    }
    return "medium";
}

ThreatLevel threatLevelFromString(const std::string& str) {
    if (str == "low")      return ThreatLevel::Low;
    if (str == "high")     return ThreatLevel::High;
    if (str == "critical") return ThreatLevel::Critical;
    return ThreatLevel::Medium;
}

Core::Result<void, Core::Error> SignatureDatabase::addSignature(const Signature& sig) {
    std::lock_guard<std::mutex> lock(mutex_);

    Signature entry = sig;
    if (entry.id == 0) {
        entry.id = nextId_++;
    } else {
        if (signatures_.count(entry.id) > 0) {
            return Core::Result<void, Core::Error>::err(
                Core::Error("Signature with ID already exists", Core::ErrorCategory::Validation));
        }
        if (entry.id >= nextId_) {
            nextId_ = entry.id + 1;
        }
    }

    if (!entry.hash.empty()) {
        hashIndex_[entry.hash] = entry.id;
    }
    signatures_[entry.id] = std::move(entry);

    return Core::Result<void, Core::Error>::ok();
}

Core::Result<void, Core::Error> SignatureDatabase::removeSignature(uint64_t id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = signatures_.find(id);
    if (it == signatures_.end()) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("Signature not found", Core::ErrorCategory::Validation));
    }

    // Remove from hash index
    if (!it->second.hash.empty()) {
        hashIndex_.erase(it->second.hash);
    }

    signatures_.erase(it);
    return Core::Result<void, Core::Error>::ok();
}

Core::Result<void, Core::Error> SignatureDatabase::updateSignature(const Signature& sig) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = signatures_.find(sig.id);
    if (it == signatures_.end()) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("Signature not found", Core::ErrorCategory::Validation));
    }

    // Remove old hash index entry
    if (!it->second.hash.empty()) {
        hashIndex_.erase(it->second.hash);
    }

    // Update and re-index
    it->second = sig;
    if (!sig.hash.empty()) {
        hashIndex_[sig.hash] = sig.id;
    }

    return Core::Result<void, Core::Error>::ok();
}

Core::Result<Signature, Core::Error> SignatureDatabase::getSignature(uint64_t id) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = signatures_.find(id);
    if (it == signatures_.end()) {
        return Core::Result<Signature, Core::Error>::err(
            Core::Error("Signature not found", Core::ErrorCategory::Validation));
    }
    return Core::Result<Signature, Core::Error>::ok(it->second);
}

std::optional<Signature> SignatureDatabase::lookupByHash(const std::string& hash) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto indexIt = hashIndex_.find(hash);
    if (indexIt == hashIndex_.end()) {
        return std::nullopt;
    }

    auto sigIt = signatures_.find(indexIt->second);
    if (sigIt == signatures_.end()) {
        return std::nullopt;
    }

    return sigIt->second;
}

Core::Result<size_t, Core::Error> SignatureDatabase::loadFromJson(
    const std::filesystem::path& filePath) {

    std::ifstream file(filePath);
    if (!file.is_open()) {
        return Core::Result<size_t, Core::Error>::err(
            Core::Error("Cannot open signature file: " + filePath.string(),
                       Core::ErrorCategory::IO));
    }

    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());

    return loadFromJsonString(content);
}

Core::Result<size_t, Core::Error> SignatureDatabase::loadFromJsonString(const std::string& jsonStr) {
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(jsonStr);
    } catch (const std::exception& e) {
        return Core::Result<size_t, Core::Error>::err(
            Core::Error(std::string("JSON parse error: ") + e.what(),
                       Core::ErrorCategory::Validation));
    }

    return parseAndLoad(j);
}

Core::Result<size_t, Core::Error> SignatureDatabase::parseAndLoad(const nlohmann::json& j) {
    if (!j.is_object() || !j.contains("signatures") || !j["signatures"].is_array()) {
        return Core::Result<size_t, Core::Error>::err(
            Core::Error("Invalid signature JSON format: expected {\"signatures\": [...]}",
                       Core::ErrorCategory::Validation));
    }

    size_t loaded = 0;
    const auto& sigArray = j["signatures"].get_array();
    for (const auto& item : sigArray) {
        Signature sig;
        if (item.contains("id") && item["id"].is_number()) {
            sig.id = static_cast<uint64_t>(item["id"].get<int64_t>());
        }
        if (item.contains("name") && item["name"].is_string()) {
            sig.name = item["name"].get<std::string>();
        }
        if (item.contains("hash") && item["hash"].is_string()) {
            sig.hash = item["hash"].get<std::string>();
        }
        if (item.contains("threat_level") && item["threat_level"].is_string()) {
            sig.threatLevel = threatLevelFromString(item["threat_level"].get<std::string>());
        }
        if (item.contains("category") && item["category"].is_string()) {
            sig.category = item["category"].get<std::string>();
        }
        if (item.contains("description") && item["description"].is_string()) {
            sig.description = item["description"].get<std::string>();
        }
        if (item.contains("date_added") && item["date_added"].is_string()) {
            sig.dateAdded = item["date_added"].get<std::string>();
        }

        auto result = addSignature(sig);
        if (result.isOk()) {
            loaded++;
        }
    }

    return Core::Result<size_t, Core::Error>::ok(loaded);
}

std::vector<Signature> SignatureDatabase::getAllSignatures() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Signature> result;
    result.reserve(signatures_.size());
    for (const auto& [id, sig] : signatures_) {
        result.push_back(sig);
    }
    return result;
}

size_t SignatureDatabase::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return signatures_.size();
}

void SignatureDatabase::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    signatures_.clear();
    hashIndex_.clear();
    nextId_ = 1;
}

} // namespace ThreatOne::Scanner
