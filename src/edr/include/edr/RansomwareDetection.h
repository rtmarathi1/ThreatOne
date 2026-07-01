#pragma once

#include <string>
#include <vector>
#include <optional>
#include <chrono>
#include <deque>
#include <mutex>
#include <unordered_set>

#include "edr/IEDREngine.h"
#include "core/Logger.h"

namespace ThreatOne::EDR {

// Stats about ransomware detection
struct RansomwareDetectionStats {
    size_t totalFilesAnalyzed = 0;
    size_t highEntropyFilesDetected = 0;
    size_t knownExtensionsDetected = 0;
    size_t massRenamesDetected = 0;
    size_t ransomNotesDetected = 0;
};

class RansomwareDetection {
public:
    RansomwareDetection();
    ~RansomwareDetection() = default;

    // Analyze a file operation for ransomware indicators
    [[nodiscard]] std::optional<RansomwareIndicator> analyzeFileOperation(const FileEvent& event);

    // Calculate Shannon entropy of a file (0-8 scale)
    [[nodiscard]] double calculateFileEntropy(const std::string& path) const;

    // Calculate entropy of raw data
    [[nodiscard]] double calculateDataEntropy(const std::vector<uint8_t>& data) const;

    // Check if a filename has a known ransomware extension
    [[nodiscard]] bool checkKnownExtensions(const std::string& filename) const;

    // Check if a filename matches known ransom note patterns
    [[nodiscard]] bool isRansomNote(const std::string& filename) const;

    // Get detection statistics
    [[nodiscard]] RansomwareDetectionStats getDetectionStats() const;

    // Configuration
    void setEntropyThreshold(double threshold);
    void setMassRenameThreshold(size_t count);
    void setMassRenameWindow(std::chrono::seconds window);

    // Clear state
    void clear();

private:
    [[nodiscard]] std::string getExtension(const std::string& filename) const;
    [[nodiscard]] std::string getFilename(const std::string& path) const;

    mutable std::mutex mutex_;
    Core::ModuleLogger logger_;

    // Known ransomware extensions
    std::unordered_set<std::string> knownExtensions_;

    // Known ransom note filenames
    std::vector<std::string> ransomNotePatterns_;

    // Recent rename events for mass-rename detection
    struct RenameRecord {
        std::string path;
        std::chrono::steady_clock::time_point timestamp;
    };
    std::deque<RenameRecord> recentRenames_;

    // Configuration
    double entropyThreshold_ = 7.5;
    size_t massRenameThreshold_ = 10;
    std::chrono::seconds massRenameWindow_{30};

    // Stats
    RansomwareDetectionStats stats_;
};

} // namespace ThreatOne::EDR
