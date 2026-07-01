#include "threat_intel/CVEDatabase.h"

#include <algorithm>

namespace ThreatOne::ThreatIntel {

CVEDatabase::CVEDatabase()
    : logger_(Core::Logger::instance().getModuleLogger("ThreatIntel.CVEDatabase")) {
}

Core::Result<void> CVEDatabase::addCVE(const CVEEntry& entry) {
    std::unique_lock lock(mutex_);

    if (entry.cveId.empty()) {
        return Core::Result<void>::err(
            Core::Error("CVE ID cannot be empty", Core::ErrorCategory::Validation));
    }

    if (cves_.contains(entry.cveId)) {
        return Core::Result<void>::err(
            Core::Error("CVE already exists: " + entry.cveId, Core::ErrorCategory::Validation));
    }

    cves_.emplace(entry.cveId, entry);
    logger_.debug("Added CVE: {}", entry.cveId);
    return Core::Result<void>::ok();
}

Core::Result<CVEEntry> CVEDatabase::getCVEById(const std::string& cveId) const {
    std::shared_lock lock(mutex_);

    auto it = cves_.find(cveId);
    if (it == cves_.end()) {
        return Core::Result<CVEEntry>::err(
            Core::Error("CVE not found: " + cveId, Core::ErrorCategory::Validation));
    }
    return Core::Result<CVEEntry>::ok(it->second);
}

std::vector<CVEEntry> CVEDatabase::searchByProduct(const std::string& product) const {
    std::shared_lock lock(mutex_);

    std::string lowerProduct = product;
    std::transform(lowerProduct.begin(), lowerProduct.end(), lowerProduct.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    std::vector<CVEEntry> result;
    for (const auto& [id, entry] : cves_) {
        for (const auto& ap : entry.affectedProducts) {
            std::string lowerProd = ap.product;
            std::transform(lowerProd.begin(), lowerProd.end(), lowerProd.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (lowerProd.find(lowerProduct) != std::string::npos) {
                result.push_back(entry);
                break;
            }
        }
    }
    return result;
}

std::vector<CVEEntry> CVEDatabase::searchByVendor(const std::string& vendor) const {
    std::shared_lock lock(mutex_);

    std::string lowerVendor = vendor;
    std::transform(lowerVendor.begin(), lowerVendor.end(), lowerVendor.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    std::vector<CVEEntry> result;
    for (const auto& [id, entry] : cves_) {
        for (const auto& ap : entry.affectedProducts) {
            std::string lowerV = ap.vendor;
            std::transform(lowerV.begin(), lowerV.end(), lowerV.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (lowerV.find(lowerVendor) != std::string::npos) {
                result.push_back(entry);
                break;
            }
        }
    }
    return result;
}

std::vector<CVEEntry> CVEDatabase::filterBySeverity(double minScore) const {
    std::shared_lock lock(mutex_);

    std::vector<CVEEntry> result;
    for (const auto& [id, entry] : cves_) {
        if (entry.cvssScore >= minScore) {
            result.push_back(entry);
        }
    }
    return result;
}

std::vector<CVEEntry> CVEDatabase::getRecentCVEs(int days) const {
    std::shared_lock lock(mutex_);

    auto now = std::chrono::system_clock::now();
    auto cutoff = now - std::chrono::hours(24 * days);

    std::vector<CVEEntry> result;
    for (const auto& [id, entry] : cves_) {
        if (entry.publishDate >= cutoff) {
            result.push_back(entry);
        }
    }
    return result;
}

Core::Result<void> CVEDatabase::updateCVE(const CVEEntry& entry) {
    std::unique_lock lock(mutex_);

    auto it = cves_.find(entry.cveId);
    if (it == cves_.end()) {
        return Core::Result<void>::err(
            Core::Error("CVE not found for update: " + entry.cveId, Core::ErrorCategory::Validation));
    }

    it->second = entry;
    logger_.debug("Updated CVE: {}", entry.cveId);
    return Core::Result<void>::ok();
}

size_t CVEDatabase::size() const {
    std::shared_lock lock(mutex_);
    return cves_.size();
}

void CVEDatabase::clear() {
    std::unique_lock lock(mutex_);
    cves_.clear();
    logger_.info("CVE database cleared");
}

} // namespace ThreatOne::ThreatIntel
