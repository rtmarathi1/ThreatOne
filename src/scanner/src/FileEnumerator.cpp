#include "scanner/FileEnumerator.h"

namespace ThreatOne::Scanner {

FileEnumerator::FileEnumerator()
    : logger_(Core::Logger::instance().getModuleLogger("FileEnumerator")) {
}

Core::Result<std::vector<std::filesystem::path>, Core::Error> FileEnumerator::enumerate(
    const EnumerationConfig& config) {

    std::vector<std::filesystem::path> results;

    auto callback = [&results](const std::filesystem::path& path) {
        results.push_back(path);
    };

    auto result = enumerateWithCallback(config, callback);
    if (result.isErr()) {
        return Core::Result<std::vector<std::filesystem::path>, Core::Error>::err(result.error());
    }

    return Core::Result<std::vector<std::filesystem::path>, Core::Error>::ok(std::move(results));
}

Core::Result<size_t, Core::Error> FileEnumerator::enumerateWithCallback(
    const EnumerationConfig& config,
    const std::function<void(const std::filesystem::path&)>& callback) {

    size_t count = 0;

    for (const auto& target : config.targets) {
        std::error_code ec;

        if (!std::filesystem::exists(target, ec)) {
            logger_.warn("Target does not exist: {}", target.string());
            continue;
        }

        // If target is a regular file, just check exclusions and add it
        if (std::filesystem::is_regular_file(target, ec)) {
            if (!matchesExclusion(target, config.exclusionPatterns)) {
                callback(target);
                count++;
            }
            continue;
        }

        if (!std::filesystem::is_directory(target, ec)) {
            logger_.warn("Target is not a file or directory: {}", target.string());
            continue;
        }

        // Recursive enumeration with depth control
        std::error_code iterEc;
        auto options = std::filesystem::directory_options::skip_permission_denied;
        if (!config.followSymlinks) {
            // Default behavior already skips symlink targets for recursion
        }

        std::filesystem::recursive_directory_iterator it(target, options, iterEc);
        if (iterEc) {
            logger_.warn("Cannot iterate directory {}: {}", target.string(), iterEc.message());
            continue;
        }

        std::filesystem::recursive_directory_iterator end;
        for (; it != end; it.increment(iterEc)) {
            if (iterEc) {
                logger_.debug("Error iterating: {}", iterEc.message());
                iterEc.clear();
                continue;
            }

            const auto& entry = *it;

            // Check depth
            if (config.maxDepth >= 0 && it.depth() > config.maxDepth) {
                it.disable_recursion_pending();
                continue;
            }

            // Skip symlinks
            if (!config.followSymlinks && entry.is_symlink(ec)) {
                if (entry.is_directory(ec)) {
                    it.disable_recursion_pending();
                }
                continue;
            }

            // Only include regular files
            if (!entry.is_regular_file(ec)) {
                continue;
            }

            const auto& path = entry.path();

            // Skip hidden files
            if (config.skipHidden) {
                auto filename = path.filename().string();
                if (!filename.empty() && filename[0] == '.') {
                    continue;
                }
            }

            // Check exclusion patterns
            if (matchesExclusion(path, config.exclusionPatterns)) {
                continue;
            }

            callback(path);
            count++;
        }
    }

    return Core::Result<size_t, Core::Error>::ok(count);
}

bool FileEnumerator::matchesExclusion(const std::filesystem::path& path,
                                       const std::vector<std::string>& patterns) {
    if (patterns.empty()) return false;

    std::string filename = path.filename().string();
    std::string pathStr = path.string();

    for (const auto& pattern : patterns) {
        // Match against filename
        if (globMatch(pattern, filename)) {
            return true;
        }
        // Match against full path
        if (globMatch(pattern, pathStr)) {
            return true;
        }
    }

    return false;
}

bool FileEnumerator::globMatch(const std::string& pattern, const std::string& text) {
    size_t pIdx = 0;
    size_t tIdx = 0;
    size_t starPIdx = std::string::npos;
    size_t starTIdx = 0;

    while (tIdx < text.size()) {
        if (pIdx < pattern.size() && (pattern[pIdx] == '?' || pattern[pIdx] == text[tIdx])) {
            pIdx++;
            tIdx++;
        } else if (pIdx < pattern.size() && pattern[pIdx] == '*') {
            starPIdx = pIdx;
            starTIdx = tIdx;
            pIdx++;
        } else if (starPIdx != std::string::npos) {
            pIdx = starPIdx + 1;
            starTIdx++;
            tIdx = starTIdx;
        } else {
            return false;
        }
    }

    while (pIdx < pattern.size() && pattern[pIdx] == '*') {
        pIdx++;
    }

    return pIdx == pattern.size();
}

} // namespace ThreatOne::Scanner
