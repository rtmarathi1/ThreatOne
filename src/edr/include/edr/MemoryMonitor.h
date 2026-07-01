#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <mutex>

#include "core/Logger.h"

namespace ThreatOne::EDR {

// Memory region information from /proc/[pid]/maps
struct MemoryRegion {
    uint64_t startAddr = 0;
    uint64_t endAddr = 0;
    std::string permissions; // e.g., "rwxp"
    std::string pathname;
    bool readable = false;
    bool writable = false;
    bool executable = false;
    bool isPrivate = false;
};

// Code injection indicator
struct InjectionIndicator {
    std::string type; // "rwx_region", "shellcode_pattern", "high_entropy", "anonymous_exec"
    std::string description;
    uint64_t address = 0;
    double severity = 0.0; // 0.0 to 1.0
};

// Entropy analysis result
struct EntropyResult {
    double entropy = 0.0; // 0.0 (uniform) to 8.0 (maximum for byte data)
    bool isPacked = false; // entropy > 7.0 suggests packed/encrypted
    uint64_t regionSize = 0;
};

class MemoryMonitor {
public:
    MemoryMonitor();
    ~MemoryMonitor() = default;

    // Get memory regions for a given process
    [[nodiscard]] std::vector<MemoryRegion> getMemoryRegions(uint64_t pid) const;

    // Scan process memory for injection indicators
    [[nodiscard]] std::vector<InjectionIndicator> scanProcessMemory(uint64_t pid) const;

    // Detect code injection for a specific process
    [[nodiscard]] std::vector<InjectionIndicator> detectCodeInjection(uint64_t pid) const;

    // Calculate entropy of memory data
    [[nodiscard]] EntropyResult calculateMemoryEntropy(const std::vector<uint8_t>& data) const;

    // Calculate entropy from /proc/[pid]/maps region (reads actual memory if accessible)
    [[nodiscard]] EntropyResult calculateMemoryEntropy(uint64_t pid, uint64_t address, uint64_t size) const;

    // Check for known shellcode patterns in data
    [[nodiscard]] bool detectShellcodePatterns(const std::vector<uint8_t>& data) const;

private:
    [[nodiscard]] std::vector<MemoryRegion> parseProcMaps(uint64_t pid) const;

    mutable std::mutex mutex_;
    Core::ModuleLogger logger_;

    // Known shellcode byte sequences (NOP sleds, syscall patterns)
    static const std::vector<std::vector<uint8_t>>& getShellcodeSignatures();
};

} // namespace ThreatOne::EDR
