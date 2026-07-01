#include "scanner/QuarantineManager.h"

#include <fstream>
#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>
#include <nlohmann/json.hpp>

namespace ThreatOne::Scanner {

QuarantineManager::QuarantineManager(const std::filesystem::path& quarantineDir)
    : quarantineDir_(quarantineDir)
    , logger_(Core::Logger::instance().getModuleLogger("QuarantineManager")) {
}

Core::Result<void, Core::Error> QuarantineManager::initialize() {
    std::error_code ec;
    if (!std::filesystem::exists(quarantineDir_, ec)) {
        std::filesystem::create_directories(quarantineDir_, ec);
        if (ec) {
            return Core::Result<void, Core::Error>::err(
                Core::Error("Failed to create quarantine directory: " + ec.message(),
                           Core::ErrorCategory::IO));
        }
        logger_.info("Created quarantine directory: {}", quarantineDir_.string());
    }
    return Core::Result<void, Core::Error>::ok();
}

Core::Result<QuarantineEntry, Core::Error> QuarantineManager::quarantine(
    const std::filesystem::path& filePath,
    const std::string& reason,
    const std::string& hash) {

    std::error_code ec;
    if (!std::filesystem::exists(filePath, ec)) {
        return Core::Result<QuarantineEntry, Core::Error>::err(
            Core::Error("File not found: " + filePath.string(), Core::ErrorCategory::IO));
    }

    // Generate entry
    QuarantineEntry entry;
    entry.id = generateId();
    entry.originalPath = std::filesystem::absolute(filePath, ec);
    entry.reason = reason;
    entry.timestamp = currentTimestamp();
    entry.hash = hash;
    entry.quarantinedPath = quarantineDir_ / (entry.id + ".quarantined");

    // Move the file to quarantine
    std::filesystem::rename(filePath, entry.quarantinedPath, ec);
    if (ec) {
        // If rename fails (cross-device), try copy + remove
        std::filesystem::copy_file(filePath, entry.quarantinedPath,
                                   std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) {
            return Core::Result<QuarantineEntry, Core::Error>::err(
                Core::Error("Failed to quarantine file: " + ec.message(),
                           Core::ErrorCategory::IO));
        }
        std::filesystem::remove(filePath, ec);
        if (ec) {
            logger_.warn("Failed to remove original file after copy: {}", ec.message());
        }
    }

    // Write metadata
    auto metaResult = writeMetadata(entry);
    if (metaResult.isErr()) {
        // Try to restore the file on metadata write failure
        std::filesystem::rename(entry.quarantinedPath, filePath, ec);
        return Core::Result<QuarantineEntry, Core::Error>::err(metaResult.error());
    }

    logger_.info("Quarantined: {} -> {}", filePath.string(), entry.quarantinedPath.string());
    return Core::Result<QuarantineEntry, Core::Error>::ok(entry);
}

Core::Result<void, Core::Error> QuarantineManager::restore(const std::string& entryId) {
    auto metaPath = quarantineDir_ / (entryId + ".json");
    auto entryResult = readMetadata(metaPath);
    if (entryResult.isErr()) {
        return Core::Result<void, Core::Error>::err(entryResult.error());
    }

    auto entry = entryResult.value();
    std::error_code ec;

    // Ensure the parent directory for original path exists
    auto parentDir = entry.originalPath.parent_path();
    if (!parentDir.empty() && !std::filesystem::exists(parentDir, ec)) {
        std::filesystem::create_directories(parentDir, ec);
    }

    // Move back to original location
    std::filesystem::rename(entry.quarantinedPath, entry.originalPath, ec);
    if (ec) {
        std::filesystem::copy_file(entry.quarantinedPath, entry.originalPath,
                                   std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) {
            return Core::Result<void, Core::Error>::err(
                Core::Error("Failed to restore file: " + ec.message(),
                           Core::ErrorCategory::IO));
        }
        std::filesystem::remove(entry.quarantinedPath, ec);
    }

    // Remove metadata file
    std::filesystem::remove(metaPath, ec);

    logger_.info("Restored: {} -> {}", entry.quarantinedPath.string(), entry.originalPath.string());
    return Core::Result<void, Core::Error>::ok();
}

Core::Result<void, Core::Error> QuarantineManager::permanentDelete(const std::string& entryId) {
    std::error_code ec;

    auto quarantinedPath = quarantineDir_ / (entryId + ".quarantined");
    auto metaPath = quarantineDir_ / (entryId + ".json");

    if (!std::filesystem::exists(quarantinedPath, ec) && !std::filesystem::exists(metaPath, ec)) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("Quarantine entry not found: " + entryId,
                       Core::ErrorCategory::Validation));
    }

    // Delete quarantined file
    if (std::filesystem::exists(quarantinedPath, ec)) {
        std::filesystem::remove(quarantinedPath, ec);
        if (ec) {
            return Core::Result<void, Core::Error>::err(
                Core::Error("Failed to delete quarantined file: " + ec.message(),
                           Core::ErrorCategory::IO));
        }
    }

    // Delete metadata
    if (std::filesystem::exists(metaPath, ec)) {
        std::filesystem::remove(metaPath, ec);
    }

    logger_.info("Permanently deleted quarantine entry: {}", entryId);
    return Core::Result<void, Core::Error>::ok();
}

Core::Result<std::vector<QuarantineEntry>, Core::Error> QuarantineManager::listEntries() const {
    std::vector<QuarantineEntry> entries;
    std::error_code ec;

    if (!std::filesystem::exists(quarantineDir_, ec)) {
        return Core::Result<std::vector<QuarantineEntry>, Core::Error>::ok(entries);
    }

    for (const auto& dirEntry : std::filesystem::directory_iterator(quarantineDir_, ec)) {
        if (dirEntry.path().extension() == ".json") {
            auto entryResult = readMetadata(dirEntry.path());
            if (entryResult.isOk()) {
                entries.push_back(entryResult.value());
            }
        }
    }

    return Core::Result<std::vector<QuarantineEntry>, Core::Error>::ok(std::move(entries));
}

Core::Result<QuarantineEntry, Core::Error> QuarantineManager::getEntry(
    const std::string& entryId) const {
    auto metaPath = quarantineDir_ / (entryId + ".json");
    return readMetadata(metaPath);
}

Core::Result<void, Core::Error> QuarantineManager::writeMetadata(const QuarantineEntry& entry) {
    auto metaPath = quarantineDir_ / (entry.id + ".json");

    nlohmann::json j;
    j["id"] = entry.id;
    j["original_path"] = entry.originalPath.string();
    j["reason"] = entry.reason;
    j["timestamp"] = entry.timestamp;
    j["hash"] = entry.hash;
    j["quarantined_path"] = entry.quarantinedPath.string();

    std::ofstream file(metaPath);
    if (!file.is_open()) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("Cannot write metadata: " + metaPath.string(),
                       Core::ErrorCategory::IO));
    }

    file << j.dump(2);
    return Core::Result<void, Core::Error>::ok();
}

Core::Result<QuarantineEntry, Core::Error> QuarantineManager::readMetadata(
    const std::filesystem::path& metaPath) const {

    std::ifstream file(metaPath);
    if (!file.is_open()) {
        return Core::Result<QuarantineEntry, Core::Error>::err(
            Core::Error("Cannot read metadata: " + metaPath.string(),
                       Core::ErrorCategory::IO));
    }

    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());

    nlohmann::json j;
    try {
        j = nlohmann::json::parse(content);
    } catch (const std::exception& e) {
        return Core::Result<QuarantineEntry, Core::Error>::err(
            Core::Error(std::string("Invalid metadata JSON: ") + e.what(),
                       Core::ErrorCategory::Validation));
    }

    QuarantineEntry entry;
    entry.id = j.value("id", std::string(""));
    entry.originalPath = j.value("original_path", std::string(""));
    entry.reason = j.value("reason", std::string(""));
    entry.timestamp = j.value("timestamp", std::string(""));
    entry.hash = j.value("hash", std::string(""));
    entry.quarantinedPath = j.value("quarantined_path", std::string(""));

    return Core::Result<QuarantineEntry, Core::Error>::ok(entry);
}

std::string QuarantineManager::currentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto timeT = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&timeT), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

std::string QuarantineManager::generateId() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFF);

    uint32_t p1 = dist(gen);
    uint32_t p2 = dist(gen);

    std::ostringstream ss;
    ss << std::hex << std::setfill('0')
       << std::setw(8) << p1 << std::setw(8) << p2;
    return ss.str();
}

} // namespace ThreatOne::Scanner
