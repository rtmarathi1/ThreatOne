#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <optional>

#include "licensing/ILicenseManager.h"

namespace ThreatOne::Licensing {

// Structured license key: TIER-XXXXX-XXXXX-XXXXX-CHECK
struct LicenseKey {
    LicenseType tier = LicenseType::Free;
    std::string segment1;
    std::string segment2;
    std::string segment3;
    std::string checksum;
    std::string rawKey;
};

struct ValidationResult {
    bool valid = false;
    std::string reason;
    std::string expiresAt;  // ISO date string YYYY-MM-DD
    int seatsAllowed = 0;
    int gracePeriodDays = 0;
};

class LicenseValidator {
public:
    LicenseValidator() = default;
    ~LicenseValidator() = default;

    // Parse a license key string into structured form
    [[nodiscard]] std::optional<LicenseKey> parseKey(const std::string& keyString) const;

    // Validate checksum of a parsed key (simple hash-based)
    [[nodiscard]] bool validateChecksum(const LicenseKey& key) const;

    // Check if the license has expired given an expiration date string
    [[nodiscard]] bool checkExpiration(const std::string& expiresAt) const;

    // Get seat limit for the given tier
    [[nodiscard]] int getSeatLimit(LicenseType tier) const;

    // Enforce seat limit: returns true if currentSeats <= allowed
    [[nodiscard]] bool enforceSeatLimit(LicenseType tier, int currentSeats) const;

    // Calculate grace period days based on tier
    [[nodiscard]] int calculateGracePeriod(LicenseType tier) const;

    // Full validation of a key string
    [[nodiscard]] ValidationResult validate(const std::string& keyString) const;

    // Parse expiration from key segments (segment2 encodes expiry)
    [[nodiscard]] std::string parseExpiration(const LicenseKey& key) const;

private:
    // Compute expected checksum for key segments
    [[nodiscard]] std::string computeChecksum(const std::string& tierStr,
                                               const std::string& seg1,
                                               const std::string& seg2,
                                               const std::string& seg3) const;

    // Convert tier string to enum
    [[nodiscard]] std::optional<LicenseType> tierFromString(const std::string& tierStr) const;

    // Convert tier enum to string prefix
    [[nodiscard]] std::string tierToString(LicenseType tier) const;
};

} // namespace ThreatOne::Licensing
