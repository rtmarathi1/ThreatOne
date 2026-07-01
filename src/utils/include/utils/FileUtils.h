#pragma once

#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <optional>
#include <cstdint>

namespace ThreatOne::Utils {

class FileUtils {
public:
    static std::optional<std::string> readFile(const std::filesystem::path& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) return std::nullopt;
        std::ostringstream ss;
        ss << file.rdbuf();
        return ss.str();
    }

    static bool writeFile(const std::filesystem::path& path, const std::string& content) {
        std::ofstream file(path, std::ios::binary);
        if (!file.is_open()) return false;
        file.write(content.data(), static_cast<std::streamsize>(content.size()));
        return file.good();
    }

    static bool exists(const std::filesystem::path& path) {
        return std::filesystem::exists(path);
    }

    static bool createDir(const std::filesystem::path& path) {
        if (std::filesystem::exists(path)) return true;
        return std::filesystem::create_directories(path);
    }

    static std::vector<std::filesystem::path> listDir(const std::filesystem::path& path) {
        std::vector<std::filesystem::path> entries;
        if (!std::filesystem::exists(path)) return entries;
        for (const auto& entry : std::filesystem::directory_iterator(path)) {
            entries.push_back(entry.path());
        }
        return entries;
    }

    static std::optional<uint64_t> getSize(const std::filesystem::path& path) {
        if (!std::filesystem::exists(path)) return std::nullopt;
        return std::filesystem::file_size(path);
    }

    static std::string hash(const std::filesystem::path& path) {
        // Stub: returns a placeholder hash
        auto content = readFile(path);
        if (!content) return "";
        // Simple hash for stub purposes
        uint64_t h = 0;
        for (char c : *content) {
            h = h * 31 + static_cast<uint64_t>(c);
        }
        char buf[17];
        std::snprintf(buf, sizeof(buf), "%016lx", h);
        return std::string(buf);
    }

    static bool copy(const std::filesystem::path& source, const std::filesystem::path& dest) {
        try {
            std::filesystem::copy(source, dest, std::filesystem::copy_options::overwrite_existing);
            return true;
        } catch (...) {
            return false;
        }
    }
};

} // namespace ThreatOne::Utils
