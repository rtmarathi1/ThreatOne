#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <algorithm>
#include <sstream>
#include <cctype>
#include <cstdio>

namespace ThreatOne::Utils {

class StringUtils {
public:
    static std::string trim(const std::string& str) {
        auto start = str.find_first_not_of(" \t\n\r");
        if (start == std::string::npos) return "";
        auto end = str.find_last_not_of(" \t\n\r");
        return str.substr(start, end - start + 1);
    }

    static std::vector<std::string> split(const std::string& str, char delimiter) {
        std::vector<std::string> tokens;
        std::istringstream stream(str);
        std::string token;
        while (std::getline(stream, token, delimiter)) {
            tokens.push_back(token);
        }
        return tokens;
    }

    static std::string join(const std::vector<std::string>& parts, const std::string& delimiter) {
        if (parts.empty()) return "";
        std::string result = parts[0];
        for (size_t i = 1; i < parts.size(); ++i) {
            result += delimiter + parts[i];
        }
        return result;
    }

    static std::string toLower(const std::string& str) {
        std::string result = str;
        std::transform(result.begin(), result.end(), result.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); });
        return result;
    }

    static std::string toUpper(const std::string& str) {
        std::string result = str;
        std::transform(result.begin(), result.end(), result.begin(),
                       [](unsigned char c) { return static_cast<char>(std::toupper(static_cast<unsigned char>(c))); });
        return result;
    }

    static bool contains(const std::string& str, const std::string& substr) {
        return str.find(substr) != std::string::npos;
    }

    static bool startsWith(const std::string& str, const std::string& prefix) {
        if (prefix.size() > str.size()) return false;
        return str.compare(0, prefix.size(), prefix) == 0;
    }

    static bool endsWith(const std::string& str, const std::string& suffix) {
        if (suffix.size() > str.size()) return false;
        return str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
    }

    template<typename... Args>
    static std::string format(const std::string& fmt, Args&&... args) {
        // Simple format using snprintf
        int size = std::snprintf(nullptr, 0, fmt.c_str(), args...) + 1;
        if (size <= 0) return fmt;
        std::string result(static_cast<size_t>(size), '\0');
        std::snprintf(result.data(), static_cast<size_t>(size), fmt.c_str(), args...);
        result.pop_back(); // Remove null terminator
        return result;
    }
};

} // namespace ThreatOne::Utils
