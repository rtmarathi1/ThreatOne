#include "edr/MemoryMonitor.h"

#include <fstream>
#include <sstream>
#include <cmath>
#include <array>
#include <algorithm>

namespace ThreatOne::EDR {

MemoryMonitor::MemoryMonitor()
    : logger_(Core::Logger::instance().getModuleLogger("MemoryMonitor")) {
    logger_.info("MemoryMonitor initialized");
}

std::vector<MemoryRegion> MemoryMonitor::getMemoryRegions(uint64_t pid) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return parseProcMaps(pid);
}

std::vector<InjectionIndicator> MemoryMonitor::scanProcessMemory(uint64_t pid) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<InjectionIndicator> indicators;
    auto regions = parseProcMaps(pid);

    for (const auto& region : regions) {
        // Check for RWX regions (write + execute = potential code injection)
        if (region.writable && region.executable) {
            InjectionIndicator ind;
            ind.type = "rwx_region";
            ind.description = "Memory region with RWX permissions at 0x" +
                std::to_string(region.startAddr);
            ind.address = region.startAddr;
            ind.severity = 0.7;

            // Anonymous RWX is more suspicious
            if (region.pathname.empty() || region.pathname == "[heap]") {
                ind.type = "anonymous_exec";
                ind.description = "Anonymous executable memory region at 0x" +
                    std::to_string(region.startAddr);
                ind.severity = 0.9;
            }

            indicators.push_back(ind);
        }
    }

    return indicators;
}

std::vector<InjectionIndicator> MemoryMonitor::detectCodeInjection(uint64_t pid) const {
    return scanProcessMemory(pid);
}

EntropyResult MemoryMonitor::calculateMemoryEntropy(const std::vector<uint8_t>& data) const {
    EntropyResult result;
    result.regionSize = data.size();

    if (data.empty()) {
        result.entropy = 0.0;
        result.isPacked = false;
        return result;
    }

    // Calculate Shannon entropy
    std::array<uint64_t, 256> frequencies{};
    for (uint8_t byte : data) {
        frequencies[byte]++;
    }

    double entropy = 0.0;
    double size = static_cast<double>(data.size());

    for (uint64_t freq : frequencies) {
        if (freq > 0) {
            double p = static_cast<double>(freq) / size;
            entropy -= p * std::log2(p);
        }
    }

    result.entropy = entropy;
    result.isPacked = (entropy > 7.0); // High entropy suggests packed/encrypted data

    return result;
}

EntropyResult MemoryMonitor::calculateMemoryEntropy(
    uint64_t pid, uint64_t address, uint64_t size) const {
    // Try to read from /proc/[pid]/mem
    // This requires ptrace or same-user permissions
    std::string memPath = "/proc/" + std::to_string(pid) + "/mem";

    std::ifstream memFile(memPath, std::ios::binary);
    if (!memFile.is_open()) {
        // Cannot access process memory, return default
        EntropyResult result;
        result.regionSize = size;
        result.entropy = 0.0;
        result.isPacked = false;
        return result;
    }

    memFile.seekg(static_cast<std::streamoff>(address));
    std::vector<uint8_t> data(size);
    memFile.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(size));
    auto bytesRead = memFile.gcount();

    if (bytesRead <= 0) {
        EntropyResult result;
        result.regionSize = 0;
        result.entropy = 0.0;
        result.isPacked = false;
        return result;
    }

    data.resize(static_cast<size_t>(bytesRead));
    return calculateMemoryEntropy(data);
}

bool MemoryMonitor::detectShellcodePatterns(const std::vector<uint8_t>& data) const {
    if (data.size() < 4) return false;

    const auto& signatures = getShellcodeSignatures();

    for (const auto& sig : signatures) {
        if (sig.size() > data.size()) continue;

        // Search for signature in data
        auto it = std::search(data.begin(), data.end(), sig.begin(), sig.end());
        if (it != data.end()) {
            return true;
        }
    }

    // Check for NOP sled (sequence of 0x90 bytes on x86)
    int nopCount = 0;
    for (uint8_t byte : data) {
        if (byte == 0x90) {
            nopCount++;
            if (nopCount >= 16) { // 16+ NOPs in a row is suspicious
                return true;
            }
        } else {
            nopCount = 0;
        }
    }

    return false;
}

std::vector<MemoryRegion> MemoryMonitor::parseProcMaps(uint64_t pid) const {
    std::vector<MemoryRegion> regions;

    std::string mapsPath = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream f(mapsPath);

    if (!f.is_open()) {
        logger_.debug("Cannot open {}", mapsPath);
        return regions;
    }

    std::string line;
    while (std::getline(f, line)) {
        if (line.empty()) continue;

        MemoryRegion region;

        // Parse format: address perms offset dev inode pathname
        // Example: 7f8a1234000-7f8a1235000 r-xp 00000000 08:01 12345 /lib/x86_64-linux-gnu/libc.so.6
        std::istringstream iss(line);
        std::string addrRange, perms, offset, dev, inode;

        iss >> addrRange >> perms >> offset >> dev >> inode;

        // Parse remaining as pathname (may contain spaces)
        std::string pathname;
        std::getline(iss, pathname);
        // Trim leading whitespace
        auto start = pathname.find_first_not_of(" \t");
        if (start != std::string::npos) {
            region.pathname = pathname.substr(start);
        }

        // Parse address range
        auto dashPos = addrRange.find('-');
        if (dashPos != std::string::npos) {
            try {
                region.startAddr = std::stoull(addrRange.substr(0, dashPos), nullptr, 16);
                region.endAddr = std::stoull(addrRange.substr(dashPos + 1), nullptr, 16);
            } catch (...) {
                continue;
            }
        }

        // Parse permissions
        region.permissions = perms;
        if (perms.size() >= 4) {
            region.readable = (perms[0] == 'r');
            region.writable = (perms[1] == 'w');
            region.executable = (perms[2] == 'x');
            region.isPrivate = (perms[3] == 'p');
        }

        regions.push_back(region);
    }

    return regions;
}

const std::vector<std::vector<uint8_t>>& MemoryMonitor::getShellcodeSignatures() {
    static const std::vector<std::vector<uint8_t>> signatures = {
        // Linux x86_64 execve syscall pattern
        {0x48, 0x31, 0xd2, 0x48, 0x31, 0xf6, 0x48, 0xbb},
        // Linux x86 int 0x80 syscall
        {0x31, 0xc0, 0x50, 0x68},
        // x86_64 syscall instruction preceded by register setup
        {0x48, 0x89, 0xc7, 0x0f, 0x05},
        // Common shellcode: xor eax,eax; push eax
        {0x31, 0xc0, 0x50},
        // Metasploit-style socket setup
        {0x6a, 0x29, 0x58, 0x99, 0x6a, 0x02}
    };
    return signatures;
}

} // namespace ThreatOne::EDR
