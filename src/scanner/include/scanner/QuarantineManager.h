#pragma once

// ThreatOne Scanner - Quarantine Manager
// Moves detected threats to quarantine directory with metadata preservation

#include <string>
#include <vector>
#include <filesystem>

#include <core/Error.h>
#include <core/Logger.h>

namespace ThreatOne::Scanner {

// Metadata stored alongside quarantined files
struct QuarantineEntry {
    std::string id;                // Unique quarantine entry ID
    std::filesystem::path originalPath;
    std::string reason;
    std::string timestamp;
    std::string hash;
    std::filesystem::path quarantinedPath;
};

// Manages quarantined (isolated) threat files
class QuarantineManager {
public:
    explicit QuarantineManager(const std::filesystem::path& quarantineDir);

    // Initialize quarantine directory (creates if needed)
    Core::Result<void, Core::Error> initialize();

    // Quarantine a file (move to quarantine dir + store metadata)
    Core::Result<QuarantineEntry, Core::Error> quarantine(
        const std::filesystem::path& filePath,
        const std::string& reason,
        const std::string& hash = "");

    // Restore a quarantined file to its original location
    Core::Result<void, Core::Error> restore(const std::string& entryId);

    // Permanently delete a quarantined file
    Core::Result<void, Core::Error> permanentDelete(const std::string& entryId);

    // List all quarantined entries
    Core::Result<std::vector<QuarantineEntry>, Core::Error> listEntries() const;

    // Get a specific entry
    Core::Result<QuarantineEntry, Core::Error> getEntry(const std::string& entryId) const;

    // Get quarantine directory path
    const std::filesystem::path& quarantineDir() const { return quarantineDir_; }

private:
    // Write metadata JSON file for a quarantined entry
    Core::Result<void, Core::Error> writeMetadata(const QuarantineEntry& entry);

    // Read metadata JSON file
    Core::Result<QuarantineEntry, Core::Error> readMetadata(
        const std::filesystem::path& metaPath) const;

    // Generate timestamp string
    static std::string currentTimestamp();

    // Generate unique ID for quarantine entries
    static std::string generateId();

    std::filesystem::path quarantineDir_;
    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Scanner
