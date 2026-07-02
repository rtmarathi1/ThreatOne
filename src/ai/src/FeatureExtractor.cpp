#include "ai/FeatureExtractor.h"

#include <array>
#include <algorithm>
#include <cmath>
#include <set>
#include <numeric>
#include <cstdint>
#include <string>
#include <vector>

namespace ThreatOne::AI {

// Common suspicious API patterns found in malware
static const std::vector<std::string> SUSPICIOUS_APIS = {
    "LoadLibrary", "GetProcAddress", "VirtualAlloc", "VirtualProtect",
    "CreateRemoteThread", "WriteProcessMemory", "ReadProcessMemory",
    "NtUnmapViewOfSection", "SetWindowsHookEx", "OpenProcess",
    "CreateProcess", "ShellExecute", "WinExec", "URLDownloadToFile",
    "InternetOpen", "HttpSendRequest", "RegSetValue", "RegCreateKey",
    "CryptEncrypt", "CryptDecrypt", "IsDebuggerPresent", "CheckRemoteDebuggerPresent"
};

// Suspicious string patterns
static const std::vector<std::string> SUSPICIOUS_STRINGS = {
    "http://", "https://", "ftp://",
    "cmd.exe", "powershell", "wscript", "cscript",
    "HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER", "CurrentVersion\\Run",
    "bitcoin", "ransom", "decrypt", "encrypt",
    "password", "credential", "token",
    "shadow", "SAM", "NTDS",
    "mimikatz", "metasploit"
};

// PE section markers
static const std::vector<std::string> PE_SECTION_MARKERS = {
    ".text", ".data", ".rdata", ".bss", ".rsrc",
    ".reloc", ".idata", ".edata", ".pdata", ".tls"
};

FeatureExtractor::FeatureExtractor()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("FeatureExtractor")) {
    logger_.info("FeatureExtractor initialized");
}

double FeatureExtractor::calculateEntropy(const std::string& data) {
    if (data.empty()) {
        return 0.0;
    }

    // Count byte frequencies
    std::array<uint64_t, 256> frequencies{};
    frequencies.fill(0);

    for (unsigned char byte : data) {
        frequencies[byte]++;
    }

    // Calculate Shannon entropy
    double entropy = 0.0;
    const double dataSize = static_cast<double>(data.size());

    for (uint64_t freq : frequencies) {
        if (freq > 0) {
            double probability = static_cast<double>(freq) / dataSize;
            entropy -= probability * std::log2(probability);
        }
    }

    return entropy;
}

FileFeatures FeatureExtractor::extractFileFeatures(const std::string& data) const {
    FileFeatures features;

    features.entropy = calculateEntropy(data);
    features.fileSize = data.size();
    features.sectionCount = countSections(data);
    features.importCount = countImports(data);
    features.suspiciousStringCount = countSuspiciousStrings(data);
    features.suspiciousStringScore = scoreSuspiciousStrings(data);
    features.hasPEHeaders = detectPEHeaders(data);
    features.urlCount = countUrls(data);
    features.registryPathCount = countRegistryPaths(data);

    logger_.debug("Extracted file features: entropy={:.3f}, size={}, sections={}, imports={}, suspicious={}",
                  features.entropy, features.fileSize, features.sectionCount,
                  features.importCount, features.suspiciousStringCount);

    return features;
}

BehaviorFeatures FeatureExtractor::extractBehaviorFeatures(
    const std::vector<BehaviorEvent>& events) const {

    BehaviorFeatures features;

    if (events.empty()) {
        return features;
    }

    features.sequenceLength = static_cast<uint32_t>(events.size());

    // Count unique event types
    std::set<std::string> uniqueTypes;
    for (const auto& event : events) {
        uniqueTypes.insert(event.type);
    }
    features.uniqueEventTypes = static_cast<uint32_t>(uniqueTypes.size());

    // Calculate timing statistics
    if (events.size() >= 2) {
        std::vector<double> interEventTimes;
        interEventTimes.reserve(events.size() - 1);

        for (size_t i = 1; i < events.size(); ++i) {
            auto diff = std::chrono::duration_cast<std::chrono::microseconds>(
                events[i].timestamp - events[i - 1].timestamp);
            interEventTimes.push_back(static_cast<double>(diff.count()) / 1000.0); // Convert to ms
        }

        // Average inter-event time
        double sum = std::accumulate(interEventTimes.begin(), interEventTimes.end(), 0.0);
        features.avgInterEventTime = sum / static_cast<double>(interEventTimes.size());

        // Timing variance (using population variance)
        double varianceSum = 0.0;
        for (double t : interEventTimes) {
            double diff = t - features.avgInterEventTime;
            varianceSum += diff * diff;
        }
        features.timingVariance = varianceSum / static_cast<double>(interEventTimes.size());

        // Event frequency: events per second
        auto totalDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
            events.back().timestamp - events.front().timestamp);
        double totalSeconds = static_cast<double>(totalDuration.count()) / 1000.0;
        if (totalSeconds > 0.0) {
            features.eventFrequency = static_cast<double>(events.size()) / totalSeconds;
        }

        // Maximum burst rate: find the highest rate in any 1-second window
        double maxBurst = 0.0;
        for (size_t i = 0; i < events.size(); ++i) {
            size_t burstCount = 0;
            auto windowEnd = events[i].timestamp + std::chrono::seconds(1);
            for (size_t j = i; j < events.size() && events[j].timestamp <= windowEnd; ++j) {
                burstCount++;
            }
            maxBurst = std::max(maxBurst, static_cast<double>(burstCount));
        }
        features.maxBurstRate = maxBurst;
    }

    logger_.debug("Extracted behavior features: freq={:.2f}, variance={:.2f}, events={}, types={}",
                  features.eventFrequency, features.timingVariance,
                  features.sequenceLength, features.uniqueEventTypes);

    return features;
}

FeatureVector FeatureExtractor::toFeatureVector(const FileFeatures& features) const {
    FeatureVector vec;
    vec["entropy"] = features.entropy;
    vec["fileSize"] = static_cast<double>(features.fileSize);
    vec["sectionCount"] = static_cast<double>(features.sectionCount);
    vec["importCount"] = static_cast<double>(features.importCount);
    vec["suspiciousStringCount"] = static_cast<double>(features.suspiciousStringCount);
    vec["suspiciousStringScore"] = features.suspiciousStringScore;
    vec["hasPEHeaders"] = features.hasPEHeaders ? 1.0 : 0.0;
    vec["urlCount"] = static_cast<double>(features.urlCount);
    vec["registryPathCount"] = static_cast<double>(features.registryPathCount);
    return vec;
}

FeatureVector FeatureExtractor::toFeatureVector(const BehaviorFeatures& features) const {
    FeatureVector vec;
    vec["eventFrequency"] = features.eventFrequency;
    vec["timingVariance"] = features.timingVariance;
    vec["sequenceLength"] = static_cast<double>(features.sequenceLength);
    vec["uniqueEventTypes"] = static_cast<double>(features.uniqueEventTypes);
    vec["avgInterEventTime"] = features.avgInterEventTime;
    vec["maxBurstRate"] = features.maxBurstRate;
    return vec;
}

uint32_t FeatureExtractor::countSections(const std::string& data) const {
    uint32_t count = 0;
    for (const auto& marker : PE_SECTION_MARKERS) {
        if (data.find(marker) != std::string::npos) {
            count++;
        }
    }
    return count;
}

uint32_t FeatureExtractor::countImports(const std::string& data) const {
    uint32_t count = 0;
    for (const auto& api : SUSPICIOUS_APIS) {
        size_t pos = 0;
        while ((pos = data.find(api, pos)) != std::string::npos) {
            count++;
            pos += api.size();
        }
    }
    return count;
}

uint32_t FeatureExtractor::countSuspiciousStrings(const std::string& data) const {
    uint32_t count = 0;
    for (const auto& pattern : SUSPICIOUS_STRINGS) {
        size_t pos = 0;
        while ((pos = data.find(pattern, pos)) != std::string::npos) {
            count++;
            pos += pattern.size();
        }
    }
    return count;
}

double FeatureExtractor::scoreSuspiciousStrings(const std::string& data) const {
    double score = 0.0;

    // Different weights for different categories of suspicious strings
    // URLs: low weight (common in legitimate software)
    for (const auto& url : {"http://", "https://", "ftp://"}) {
        if (data.find(url) != std::string::npos) {
            score += 0.5;
        }
    }

    // Command shells: medium weight
    for (const auto& shell : {"cmd.exe", "powershell", "wscript", "cscript"}) {
        if (data.find(shell) != std::string::npos) {
            score += 1.5;
        }
    }

    // Registry persistence: high weight
    for (const auto& reg : {"HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER", "CurrentVersion\\Run"}) {
        if (data.find(reg) != std::string::npos) {
            score += 2.0;
        }
    }

    // Crypto/ransom: very high weight
    for (const auto& crypto : {"bitcoin", "ransom", "decrypt", "encrypt"}) {
        if (data.find(crypto) != std::string::npos) {
            score += 3.0;
        }
    }

    // Credential theft: high weight
    for (const auto& cred : {"password", "credential", "token", "shadow", "SAM", "NTDS", "mimikatz"}) {
        if (data.find(cred) != std::string::npos) {
            score += 2.5;
        }
    }

    return score;
}

uint32_t FeatureExtractor::countUrls(const std::string& data) const {
    uint32_t count = 0;
    for (const auto& prefix : {"http://", "https://", "ftp://"}) {
        size_t pos = 0;
        std::string pattern(prefix);
        while ((pos = data.find(pattern, pos)) != std::string::npos) {
            count++;
            pos += pattern.size();
        }
    }
    return count;
}

uint32_t FeatureExtractor::countRegistryPaths(const std::string& data) const {
    uint32_t count = 0;
    for (const auto& prefix : {"HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER",
                                "HKEY_CLASSES_ROOT", "HKEY_USERS"}) {
        size_t pos = 0;
        std::string pattern(prefix);
        while ((pos = data.find(pattern, pos)) != std::string::npos) {
            count++;
            pos += pattern.size();
        }
    }
    return count;
}

bool FeatureExtractor::detectPEHeaders(const std::string& data) const {
    // Check for MZ header (DOS header magic bytes)
    if (data.size() >= 2) {
        if (data[0] == 'M' && data[1] == 'Z') {
            return true;
        }
    }

    // Check for PE signature
    if (data.find("PE\0\0", 0, 4) != std::string::npos) {
        return true;
    }

    return false;
}

} // namespace ThreatOne::AI
