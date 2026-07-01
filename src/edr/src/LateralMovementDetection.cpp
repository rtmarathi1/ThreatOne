#include "edr/LateralMovementDetection.h"

#include <algorithm>
#include <chrono>
#include <sstream>
#include <iomanip>

namespace ThreatOne::EDR {

namespace {

std::string currentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::put_time(std::gmtime(&time), "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

} // anonymous namespace

LateralMovementDetection::LateralMovementDetection()
    : logger_(Core::Logger::instance().getModuleLogger("LateralMovementDetection"))
{
    // Initialize credential file paths
    credentialPaths_ = {
        "/etc/shadow", "/etc/passwd", "/etc/sudoers",
        ".ssh/id_rsa", ".ssh/id_dsa", ".ssh/id_ecdsa", ".ssh/id_ed25519",
        ".ssh/authorized_keys", ".ssh/known_hosts",
        ".gnupg/secring.gpg", ".aws/credentials",
        "/etc/krb5.keytab"
    };

    // Initialize remote execution patterns
    remoteExecPatterns_ = {
        "psexec", "wmic", "winrm", "smbexec",
        "reverse_tcp", "reverse_shell", "bind_shell",
        "/dev/tcp/", "mkfifo", "nc -e", "ncat -e",
        "bash -i >&", "python -c 'import socket"
    };

    logger_.info("LateralMovementDetection initialized");
}

std::optional<LateralMovementIndicator> LateralMovementDetection::analyzeConnection(const NetworkEvent& event) {
    std::lock_guard lock(mutex_);

    LateralMovementIndicator indicator;
    indicator.sourceHost = event.sourceIP;
    indicator.destHost = event.destIP;
    indicator.timestamp = "now"; // Placeholder

    // Check for SSH brute force
    if (event.destPort == 22 || event.protocol == "ssh") {
        ConnectionAttempt attempt;
        attempt.destIP = event.destIP;
        attempt.timestamp = event.timestamp;
        sshAttempts_.push_back(attempt);

        // Clean old entries
        auto cutoff = std::chrono::steady_clock::now() - bruteForceWindow_;
        while (!sshAttempts_.empty() && sshAttempts_.front().timestamp < cutoff) {
            sshAttempts_.pop_front();
        }

        if (isSshBruteForce(event.destIP)) {
            indicator.technique = "ssh_brute_force";
            logger_.warn("SSH brute force detected to {}", event.destIP);
            return indicator;
        }
    }

    // Check for new internal IP connections (not in baseline)
    if (isInternalIP(event.destIP) && !isBaselineConnection(event.destIP, event.destPort)) {
        indicator.technique = "new_internal_connection";
        logger_.info("New internal connection detected: {} -> {}:{}", 
                     event.sourceIP, event.destIP, event.destPort);
        return indicator;
    }

    return std::nullopt;
}

void LateralMovementDetection::addBaselineConnection(const std::string& destIP, uint16_t destPort) {
    std::lock_guard lock(mutex_);
    BaselineEntry entry;
    entry.destIP = destIP;
    entry.destPort = destPort;
    baseline_.push_back(entry);
}

std::optional<LateralMovementIndicator> LateralMovementDetection::detectCredentialAccess(
        const std::string& filePath, const std::string& processName) const {

    for (const auto& credPath : credentialPaths_) {
        if (filePath.find(credPath) != std::string::npos) {
            LateralMovementIndicator indicator;
            indicator.sourceHost = "local";
            indicator.destHost = "local";
            indicator.technique = "Credential file access: " + filePath + " by " + processName;
            indicator.timestamp = currentTimestamp();
            indicator.severity = "high";
            logger_.warn("Credential access detected: {} accessed by {}", filePath, processName);
            return indicator;
        }
    }

    return std::nullopt;
}

std::optional<LateralMovementIndicator> LateralMovementDetection::detectRemoteExecution(
        const std::string& commandLine, const std::string& processName) const {

    std::string lowerCmd = commandLine;
    std::transform(lowerCmd.begin(), lowerCmd.end(), lowerCmd.begin(), ::tolower);

    for (const auto& pattern : remoteExecPatterns_) {
        std::string lowerPattern = pattern;
        std::transform(lowerPattern.begin(), lowerPattern.end(), lowerPattern.begin(), ::tolower);

        if (lowerCmd.find(lowerPattern) != std::string::npos) {
            LateralMovementIndicator indicator;
            indicator.sourceHost = "local";
            indicator.destHost = "remote";
            indicator.technique = "Remote execution pattern: " + pattern + " in " + processName;
            indicator.timestamp = currentTimestamp();
            indicator.severity = "critical";
            logger_.warn("Remote execution detected: {} in process {}", pattern, processName);
            return indicator;
        }
    }

    return std::nullopt;
}

void LateralMovementDetection::setBruteForceThreshold(size_t attempts) {
    bruteForceThreshold_ = attempts;
}

void LateralMovementDetection::setBruteForceWindow(std::chrono::seconds window) {
    bruteForceWindow_ = window;
}

void LateralMovementDetection::clear() {
    std::lock_guard lock(mutex_);
    sshAttempts_.clear();
    baseline_.clear();
    knownInternalIPs_.clear();
}

bool LateralMovementDetection::isInternalIP(const std::string& ip) const {
    // Check for RFC 1918 private address ranges
    if (ip.rfind("10.", 0) == 0) return true;
    if (ip.rfind("192.168.", 0) == 0) return true;
    if (ip.rfind("172.", 0) == 0) {
        // Check 172.16.0.0 - 172.31.255.255
        auto dotPos = ip.find('.', 4);
        if (dotPos != std::string::npos) {
            try {
                int second = std::stoi(ip.substr(4, dotPos - 4));
                if (second >= 16 && second <= 31) return true;
            } catch (...) {}
        }
    }
    if (ip == "127.0.0.1" || ip.rfind("127.", 0) == 0) return true;
    return false;
}

bool LateralMovementDetection::isBaselineConnection(const std::string& destIP, uint16_t destPort) const {
    for (const auto& entry : baseline_) {
        if (entry.destIP == destIP && entry.destPort == destPort) {
            return true;
        }
    }
    return false;
}

bool LateralMovementDetection::isSshBruteForce(const std::string& destIP) const {
    auto now = std::chrono::steady_clock::now();
    auto windowStart = now - bruteForceWindow_;

    size_t count = 0;
    for (const auto& attempt : sshAttempts_) {
        if (attempt.destIP == destIP && attempt.timestamp >= windowStart) {
            count++;
        }
    }

    return count >= bruteForceThreshold_;
}

} // namespace ThreatOne::EDR
