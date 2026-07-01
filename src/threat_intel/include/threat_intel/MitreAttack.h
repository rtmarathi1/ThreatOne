#pragma once

// ThreatOne Threat Intel - MITRE ATT&CK Integration
// Maps detections to MITRE ATT&CK techniques/tactics with a local matrix

#include <string>
#include <vector>
#include <unordered_map>
#include <shared_mutex>

#include <core/Error.h>
#include <core/Logger.h>

namespace ThreatOne::ThreatIntel {

// MITRE ATT&CK Tactic (e.g., Initial Access, Execution)
struct Tactic {
    std::string id;           // e.g., "TA0001"
    std::string name;         // e.g., "Initial Access"
    std::string description;
    std::vector<std::string> techniques; // Technique IDs belonging to this tactic
};

// MITRE ATT&CK Technique (e.g., T1059 - Command and Scripting Interpreter)
struct Technique {
    std::string id;           // e.g., "T1059"
    std::string name;         // e.g., "Command and Scripting Interpreter"
    std::string description;
    std::vector<std::string> tactics;      // Tactic IDs this technique maps to
    std::vector<std::string> dataSources;  // Data sources for detection
    std::string detection;                 // Detection guidance
};

// Manages the MITRE ATT&CK matrix with technique/tactic lookups
class MitreAttackMatrix {
public:
    MitreAttackMatrix();

    // Add a technique to the matrix
    void addTechnique(const Technique& technique);

    // Get a technique by its ID (e.g., "T1059")
    [[nodiscard]] Core::Result<Technique> getTechniqueById(const std::string& id) const;

    // Get all techniques for a given tactic ID
    [[nodiscard]] std::vector<Technique> getTechniquesByTactic(const std::string& tacticId) const;

    // Get all tactics
    [[nodiscard]] std::vector<Tactic> getAllTactics() const;

    // Map detection info string to matching techniques
    [[nodiscard]] std::vector<Technique> mapDetectionToTechnique(const std::string& detectionInfo) const;

    // Search techniques by keyword in name or description
    [[nodiscard]] std::vector<Technique> searchTechniques(const std::string& query) const;

    // Get total technique count
    [[nodiscard]] size_t techniqueCount() const;

    // Get total tactic count
    [[nodiscard]] size_t tacticCount() const;

private:
    void populateDefaultMatrix();
    void addTactic(const Tactic& tactic);

    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, Technique> techniques_;
    std::unordered_map<std::string, Tactic> tactics_;
    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::ThreatIntel
