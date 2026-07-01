#include "edr/RansomwareDetection.h"

#include <fstream>
#include <cmath>
#include <algorithm>
#include <array>
#include <filesystem>

namespace ThreatOne::EDR {

RansomwareDetection::RansomwareDetection()
    : logger_(Core::Logger::instance().getModuleLogger("RansomwareDetection"))
{
    // Initialize known ransomware extensions
    knownExtensions_ = {
        ".encrypted", ".locked", ".crypto", ".crypt", ".locky",
        ".cerber", ".zepto", ".thor", ".aaa", ".abc", ".zzz",
        ".enc", ".crypted", ".pays", ".ransom", ".wallet",
        ".petya", ".cry", ".wncry", ".wcry", ".wncryt",
        ".lock", ".coded", ".cryptolocker", ".crinf", ".r5a",
        ".XRNT", ".XTBL", ".crypt1", ".da_vinci_code",
        ".magic", ".surprise", ".no_more_ransom", ".the_bresa"
    };

    // Initialize ransom note filename patterns
    ransomNotePatterns_ = {
        "README_DECRYPT", "HOW_TO_RECOVER", "HOW_TO_DECRYPT",
        "DECRYPT_INSTRUCTION", "HELP_DECRYPT", "RECOVERY_KEY",
        "YOUR_FILES_ARE_ENCRYPTED", "RANSOM_NOTE", "READ_ME_TO_DECRYPT",
        "HELP_YOUR_FILES", "DECRYPT_YOUR_FILES", "FILES_ENCRYPTED",
        "!README!", "_readme_", "ATTENTION!!!", "HELP_FILE_RESTORE"
    };

    logger_.info("RansomwareDetection initialized with {} known extensions", knownExtensions_.size());
}

std::optional<RansomwareIndicator> RansomwareDetection::analyzeFileOperation(const FileEvent& event) {
    std::lock_guard lock(mutex_);
    stats_.totalFilesAnalyzed++;

    RansomwareIndicator indicator;
    bool detected = false;

    std::string filename = getFilename(event.path);

    // Check for known ransomware extensions
    if (checkKnownExtensions(filename)) {
        stats_.knownExtensionsDetected++;
        indicator.indicator = "known_ransomware_extension";
        indicator.confidence = "high";
        indicator.affectedPaths.push_back(event.path);
        detected = true;
    }

    // Check for ransom note creation
    if ((event.action == "create" || event.action == "write") && isRansomNote(filename)) {
        stats_.ransomNotesDetected++;
        indicator.indicator = "ransom_note_creation";
        indicator.confidence = "high";
        indicator.affectedPaths.push_back(event.path);
        detected = true;
    }

    // Track rename operations for mass-rename detection
    if (event.action == "rename") {
        RenameRecord record;
        record.path = event.path;
        record.timestamp = std::chrono::steady_clock::now();
        recentRenames_.push_back(record);

        // Clean old entries
        auto cutoff = std::chrono::steady_clock::now() - massRenameWindow_;
        while (!recentRenames_.empty() && recentRenames_.front().timestamp < cutoff) {
            recentRenames_.pop_front();
        }

        // Check for mass rename
        if (recentRenames_.size() >= massRenameThreshold_) {
            stats_.massRenamesDetected++;
            indicator.indicator = "mass_file_rename";
            indicator.confidence = "high";
            for (const auto& r : recentRenames_) {
                indicator.affectedPaths.push_back(r.path);
            }
            detected = true;
        }
    }

    if (detected) {
        return indicator;
    }
    return std::nullopt;
}

double RansomwareDetection::calculateFileEntropy(const std::string& path) const {
    try {
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) return 0.0;

        std::vector<uint8_t> data(
            (std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>());

        return calculateDataEntropy(data);
    } catch (...) {
        return 0.0;
    }
}

double RansomwareDetection::calculateDataEntropy(const std::vector<uint8_t>& data) const {
    if (data.empty()) return 0.0;

    // Count byte frequencies
    std::array<size_t, 256> frequencies{};
    for (uint8_t byte : data) {
        frequencies[byte]++;
    }

    // Calculate Shannon entropy
    double entropy = 0.0;
    double dataSize = static_cast<double>(data.size());

    for (size_t count : frequencies) {
        if (count == 0) continue;
        double probability = static_cast<double>(count) / dataSize;
        entropy -= probability * std::log2(probability);
    }

    return entropy; // 0.0 to 8.0 scale
}

bool RansomwareDetection::checkKnownExtensions(const std::string& filename) const {
    std::string ext = getExtension(filename);
    if (ext.empty()) return false;

    // Convert to lowercase for comparison
    std::string lowerExt = ext;
    std::transform(lowerExt.begin(), lowerExt.end(), lowerExt.begin(), ::tolower);

    return knownExtensions_.count(lowerExt) > 0;
}

bool RansomwareDetection::isRansomNote(const std::string& filename) const {
    std::string upper = filename;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

    for (const auto& pattern : ransomNotePatterns_) {
        std::string upperPattern = pattern;
        std::transform(upperPattern.begin(), upperPattern.end(), upperPattern.begin(), ::toupper);
        if (upper.find(upperPattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

RansomwareDetectionStats RansomwareDetection::getDetectionStats() const {
    std::lock_guard lock(mutex_);
    return stats_;
}

void RansomwareDetection::setEntropyThreshold(double threshold) {
    entropyThreshold_ = threshold;
}

void RansomwareDetection::setMassRenameThreshold(size_t count) {
    massRenameThreshold_ = count;
}

void RansomwareDetection::setMassRenameWindow(std::chrono::seconds window) {
    massRenameWindow_ = window;
}

void RansomwareDetection::clear() {
    std::lock_guard lock(mutex_);
    recentRenames_.clear();
    stats_ = RansomwareDetectionStats{};
}

std::string RansomwareDetection::getExtension(const std::string& filename) const {
    auto pos = filename.rfind('.');
    if (pos == std::string::npos || pos == 0) return "";
    return filename.substr(pos);
}

std::string RansomwareDetection::getFilename(const std::string& path) const {
    auto pos = path.rfind('/');
    if (pos == std::string::npos) return path;
    return path.substr(pos + 1);
}

} // namespace ThreatOne::EDR
