#pragma once

// ThreatOne Threat Intel - CVE Database
// Local CVE store with CVSS scoring, product matching, and search

#include <string>
#include <vector>
#include <unordered_map>
#include <shared_mutex>
#include <chrono>

#include <core/Error.h>
#include <core/Logger.h>

namespace ThreatOne::ThreatIntel {

// Affected product information
struct AffectedProduct {
    std::string vendor;
    std::string product;
    std::string version;
};

// CVE entry with CVSS scoring
struct CVEEntry {
    std::string cveId;         // e.g., "CVE-2023-12345"
    std::string description;
    double cvssScore = 0.0;    // 0.0 - 10.0
    std::string severity;      // Low, Medium, High, Critical
    std::vector<AffectedProduct> affectedProducts;
    std::chrono::system_clock::time_point publishDate;
    std::chrono::system_clock::time_point lastModified;
    std::vector<std::string> references;
};

// Thread-safe CVE database with CRUD and search operations
class CVEDatabase {
public:
    CVEDatabase();

    // Add a CVE entry
    [[nodiscard]] Core::Result<void> addCVE(const CVEEntry& entry);

    // Get CVE by ID
    [[nodiscard]] Core::Result<CVEEntry> getCVEById(const std::string& cveId) const;

    // Search by product name (substring match)
    [[nodiscard]] std::vector<CVEEntry> searchByProduct(const std::string& product) const;

    // Search by vendor name (substring match)
    [[nodiscard]] std::vector<CVEEntry> searchByVendor(const std::string& vendor) const;

    // Filter CVEs by minimum CVSS severity score
    [[nodiscard]] std::vector<CVEEntry> filterBySeverity(double minScore) const;

    // Get CVEs published within the last N days
    [[nodiscard]] std::vector<CVEEntry> getRecentCVEs(int days) const;

    // Update an existing CVE entry
    [[nodiscard]] Core::Result<void> updateCVE(const CVEEntry& entry);

    // Get total count
    [[nodiscard]] size_t size() const;

    // Clear all entries
    void clear();

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, CVEEntry> cves_;
    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::ThreatIntel
