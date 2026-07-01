#pragma once

// ThreatOne Scanner - File Enumerator
// Recursive file enumeration with exclusion patterns and depth control

#include <string>
#include <vector>
#include <filesystem>
#include <functional>

#include <core/Error.h>
#include <core/Logger.h>

namespace ThreatOne::Scanner {

// Configuration for file enumeration
struct EnumerationConfig {
    std::vector<std::filesystem::path> targets;       // Root directories/files to enumerate
    std::vector<std::string> exclusionPatterns;       // Glob-style patterns: *.ext, dir/*, /path/*
    int maxDepth = -1;                                // -1 = unlimited
    bool followSymlinks = false;                      // Skip symlinks by default
    bool skipHidden = false;                          // Skip hidden files (starting with .)
};

// File enumerator using std::filesystem
class FileEnumerator {
public:
    FileEnumerator();

    // Enumerate files matching the configuration
    Core::Result<std::vector<std::filesystem::path>, Core::Error> enumerate(
        const EnumerationConfig& config);

    // Enumerate with a callback (memory-efficient for large directories)
    Core::Result<size_t, Core::Error> enumerateWithCallback(
        const EnumerationConfig& config,
        const std::function<void(const std::filesystem::path&)>& callback);

    // Check if a path matches any exclusion pattern
    static bool matchesExclusion(const std::filesystem::path& path,
                                 const std::vector<std::string>& patterns);

private:
    // Simple glob matching (supports *, ?)
    static bool globMatch(const std::string& pattern, const std::string& text);

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Scanner
