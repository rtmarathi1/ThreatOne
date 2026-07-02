#include "threat_intel/MitreAttack.h"

#include <algorithm>
#include <cctype>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <vector>

namespace ThreatOne::ThreatIntel {

MitreAttackMatrix::MitreAttackMatrix()
    : logger_(Core::Logger::instance().getModuleLogger("ThreatIntel.MitreAttack")) {
    populateDefaultMatrix();
}

void MitreAttackMatrix::addTactic(const Tactic& tactic) {
    tactics_[tactic.id] = tactic;
}

void MitreAttackMatrix::addTechnique(const Technique& technique) {
    std::unique_lock lock(mutex_);
    techniques_[technique.id] = technique;

    // Update tactic-to-technique mappings
    for (const auto& tacticId : technique.tactics) {
        auto it = tactics_.find(tacticId);
        if (it != tactics_.end()) {
            auto& techList = it->second.techniques;
            if (std::find(techList.begin(), techList.end(), technique.id) == techList.end()) {
                techList.push_back(technique.id);
            }
        }
    }
    logger_.debug("Added technique: {} - {}", technique.id, technique.name);
}

Core::Result<Technique> MitreAttackMatrix::getTechniqueById(const std::string& id) const {
    std::shared_lock lock(mutex_);

    auto it = techniques_.find(id);
    if (it == techniques_.end()) {
        return Core::Result<Technique>::err(
            Core::Error("Technique not found: " + id, Core::ErrorCategory::Validation));
    }
    return Core::Result<Technique>::ok(it->second);
}

std::vector<Technique> MitreAttackMatrix::getTechniquesByTactic(const std::string& tacticId) const {
    std::shared_lock lock(mutex_);

    std::vector<Technique> result;
    auto tacticIt = tactics_.find(tacticId);
    if (tacticIt == tactics_.end()) {
        return result;
    }

    for (const auto& techId : tacticIt->second.techniques) {
        auto techIt = techniques_.find(techId);
        if (techIt != techniques_.end()) {
            result.push_back(techIt->second);
        }
    }
    return result;
}

std::vector<Tactic> MitreAttackMatrix::getAllTactics() const {
    std::shared_lock lock(mutex_);

    std::vector<Tactic> result;
    result.reserve(tactics_.size());
    for (const auto& [id, tactic] : tactics_) {
        result.push_back(tactic);
    }
    return result;
}

std::vector<Technique> MitreAttackMatrix::mapDetectionToTechnique(const std::string& detectionInfo) const {
    std::shared_lock lock(mutex_);

    std::vector<Technique> result;
    // Convert detection info to lowercase for case-insensitive matching
    std::string lowerDetection = detectionInfo;
    std::transform(lowerDetection.begin(), lowerDetection.end(), lowerDetection.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    for (const auto& [id, technique] : techniques_) {
        // Check if detection info matches the technique's detection guidance
        std::string lowerDetect = technique.detection;
        std::transform(lowerDetect.begin(), lowerDetect.end(), lowerDetect.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        if (!lowerDetect.empty() && lowerDetection.find(lowerDetect) != std::string::npos) {
            result.push_back(technique);
            continue;
        }

        // Also check technique name
        std::string lowerName = technique.name;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        if (lowerDetection.find(lowerName) != std::string::npos) {
            result.push_back(technique);
            continue;
        }

        // Check data sources
        for (const auto& source : technique.dataSources) {
            std::string lowerSource = source;
            std::transform(lowerSource.begin(), lowerSource.end(), lowerSource.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (lowerDetection.find(lowerSource) != std::string::npos) {
                result.push_back(technique);
                break;
            }
        }
    }
    return result;
}

std::vector<Technique> MitreAttackMatrix::searchTechniques(const std::string& query) const {
    std::shared_lock lock(mutex_);

    std::vector<Technique> result;
    std::string lowerQuery = query;
    std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    for (const auto& [id, technique] : techniques_) {
        std::string lowerName = technique.name;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        std::string lowerDesc = technique.description;
        std::transform(lowerDesc.begin(), lowerDesc.end(), lowerDesc.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        std::string lowerId = technique.id;
        std::transform(lowerId.begin(), lowerId.end(), lowerId.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        if (lowerName.find(lowerQuery) != std::string::npos ||
            lowerDesc.find(lowerQuery) != std::string::npos ||
            lowerId.find(lowerQuery) != std::string::npos) {
            result.push_back(technique);
        }
    }
    return result;
}

size_t MitreAttackMatrix::techniqueCount() const {
    std::shared_lock lock(mutex_);
    return techniques_.size();
}

size_t MitreAttackMatrix::tacticCount() const {
    std::shared_lock lock(mutex_);
    return tactics_.size();
}

void MitreAttackMatrix::populateDefaultMatrix() {
    // Define tactics
    addTactic({"TA0001", "Initial Access", "Techniques used to gain initial foothold", {}});
    addTactic({"TA0002", "Execution", "Techniques that run malicious code", {}});
    addTactic({"TA0003", "Persistence", "Techniques to maintain access across restarts", {}});
    addTactic({"TA0004", "Privilege Escalation", "Techniques to gain higher-level permissions", {}});
    addTactic({"TA0005", "Defense Evasion", "Techniques to avoid detection", {}});
    addTactic({"TA0006", "Credential Access", "Techniques to steal credentials", {}});
    addTactic({"TA0007", "Discovery", "Techniques to gain knowledge about the system", {}});
    addTactic({"TA0008", "Lateral Movement", "Techniques to move through the network", {}});
    addTactic({"TA0009", "Collection", "Techniques to gather data of interest", {}});
    addTactic({"TA0010", "Exfiltration", "Techniques to steal data", {}});
    addTactic({"TA0011", "Command and Control", "Techniques to communicate with controlled systems", {}});

    // Pre-populate with common ATT&CK techniques (20+ entries)

    // Initial Access (TA0001)
    addTechnique({"T1566", "Phishing", "Adversaries send phishing messages to gain access",
        {"TA0001"}, {"Email Gateway", "Network Traffic"}, "phishing"});
    addTechnique({"T1190", "Exploit Public-Facing Application",
        "Adversaries exploit vulnerabilities in internet-facing applications",
        {"TA0001"}, {"Application Log", "Network Traffic"}, "exploit"});
    addTechnique({"T1078", "Valid Accounts",
        "Adversaries use legitimate credentials to gain access",
        {"TA0001", "TA0003", "TA0004", "TA0005"}, {"Authentication Logs", "Logon Session"}, "valid accounts"});
    addTechnique({"T1189", "Drive-by Compromise",
        "Adversaries gain access through user visiting compromised website",
        {"TA0001"}, {"Network Traffic", "Process Creation"}, "drive-by"});

    // Execution (TA0002)
    addTechnique({"T1059", "Command and Scripting Interpreter",
        "Adversaries abuse command and script interpreters to execute commands",
        {"TA0002"}, {"Process Creation", "Command Line"}, "command line"});
    addTechnique({"T1204", "User Execution",
        "Adversary relies on user to execute malicious content",
        {"TA0002"}, {"Process Creation", "File Creation"}, "user execution"});
    addTechnique({"T1053", "Scheduled Task/Job",
        "Adversaries abuse task scheduling to execute malicious code",
        {"TA0002", "TA0003", "TA0004"}, {"Scheduled Job", "Process Creation"}, "scheduled task"});
    addTechnique({"T1047", "Windows Management Instrumentation",
        "Adversaries abuse WMI to execute malicious commands",
        {"TA0002"}, {"WMI Activity", "Process Creation"}, "wmi"});

    // Persistence (TA0003)
    addTechnique({"T1547", "Boot or Logon Autostart Execution",
        "Adversaries configure system settings to automatically execute programs at boot or logon",
        {"TA0003", "TA0004"}, {"Registry", "File System"}, "autostart"});
    addTechnique({"T1136", "Create Account",
        "Adversaries create accounts to maintain access",
        {"TA0003"}, {"User Account", "Process Creation"}, "create account"});
    addTechnique({"T1543", "Create or Modify System Process",
        "Adversaries create or modify system processes to maintain persistence",
        {"TA0003", "TA0004"}, {"Service", "Process Creation"}, "system process"});

    // Privilege Escalation (TA0004)
    addTechnique({"T1548", "Abuse Elevation Control Mechanism",
        "Adversaries bypass elevated access controls",
        {"TA0004", "TA0005"}, {"Process Creation", "Command Line"}, "elevation"});
    addTechnique({"T1068", "Exploitation for Privilege Escalation",
        "Adversaries exploit software vulnerabilities to escalate privileges",
        {"TA0004"}, {"Process Creation", "Application Log"}, "privilege escalation exploit"});

    // Defense Evasion (TA0005)
    addTechnique({"T1070", "Indicator Removal",
        "Adversaries delete or modify artifacts to hinder detection",
        {"TA0005"}, {"File System", "Windows Event Log"}, "indicator removal"});
    addTechnique({"T1027", "Obfuscated Files or Information",
        "Adversaries obfuscate content to evade detection",
        {"TA0005"}, {"File Content", "Process Creation"}, "obfuscation"});
    addTechnique({"T1562", "Impair Defenses",
        "Adversaries disable or modify security tools",
        {"TA0005"}, {"Security Software", "Process Creation"}, "impair defenses"});
    addTechnique({"T1055", "Process Injection",
        "Adversaries inject code into processes to evade detection",
        {"TA0005", "TA0004"}, {"Process Access", "Module Load"}, "process injection"});

    // Credential Access (TA0006)
    addTechnique({"T1003", "OS Credential Dumping",
        "Adversaries dump credentials from the operating system",
        {"TA0006"}, {"Process Access", "Command Line"}, "credential dump"});
    addTechnique({"T1110", "Brute Force",
        "Adversaries use brute force to obtain credentials",
        {"TA0006"}, {"Authentication Logs", "Network Traffic"}, "brute force"});

    // Discovery (TA0007)
    addTechnique({"T1082", "System Information Discovery",
        "Adversaries gather detailed system information",
        {"TA0007"}, {"Process Creation", "Command Line"}, "system information"});

    // Lateral Movement (TA0008)
    addTechnique({"T1021", "Remote Services",
        "Adversaries use valid accounts to log into remote services",
        {"TA0008"}, {"Authentication Logs", "Network Traffic"}, "remote services"});

    // Collection (TA0009)
    addTechnique({"T1005", "Data from Local System",
        "Adversaries search local system sources for data to exfiltrate",
        {"TA0009"}, {"File Access", "Process Creation"}, "local data collection"});

    // Exfiltration (TA0010)
    addTechnique({"T1041", "Exfiltration Over C2 Channel",
        "Adversaries exfiltrate data over their command and control channel",
        {"TA0010"}, {"Network Traffic", "Command Line"}, "exfiltration c2"});

    // Command and Control (TA0011)
    addTechnique({"T1071", "Application Layer Protocol",
        "Adversaries communicate using application layer protocols",
        {"TA0011"}, {"Network Traffic", "Packet Capture"}, "c2 protocol"});
    addTechnique({"T1105", "Ingress Tool Transfer",
        "Adversaries transfer tools from external systems into compromised environment",
        {"TA0011"}, {"Network Traffic", "File Creation"}, "tool transfer"});

    logger_.info("MITRE ATT&CK matrix populated with {} techniques across {} tactics",
                 techniques_.size(), tactics_.size());
}

} // namespace ThreatOne::ThreatIntel
