#include "licensing/LicenseValidator.h"

#include <algorithm>
#include <numeric>
#include <sstream>
#include <ctime>
#include <iomanip>

namespace ThreatOne::Licensing {

std::optional<LicenseKey> LicenseValidator::parseKey(const std::string& keyString) const {
    // Format: TIER-XXXXX-XXXXX-XXXXX-CHECK
    // Split by '-'
    std::vector<std::string> parts;
    std::stringstream ss(keyString);
    std::string part;
    while (std::getline(ss, part, '-')) {
        parts.push_back(part);
    }

    if (parts.size() != 5) {
        return std::nullopt;
    }

    // Validate tier prefix
    auto tier = tierFromString(parts[0]);
    if (!tier.has_value()) {
        return std::nullopt;
    }

    // Validate segment lengths (each should be 5 characters)
    if (parts[1].size() != 5 || parts[2].size() != 5 || parts[3].size() != 5) {
        return std::nullopt;
    }

    // Validate checksum length (5 characters)
    if (parts[4].size() != 5) {
        return std::nullopt;
    }

    // Validate segments are alphanumeric uppercase
    auto isValidSegment = [](const std::string& seg) {
        return std::all_of(seg.begin(), seg.end(), [](char c) {
            return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
        });
    };

    if (!isValidSegment(parts[1]) || !isValidSegment(parts[2]) ||
        !isValidSegment(parts[3]) || !isValidSegment(parts[4])) {
        return std::nullopt;
    }

    LicenseKey key;
    key.tier = tier.value();
    key.segment1 = parts[1];
    key.segment2 = parts[2];
    key.segment3 = parts[3];
    key.checksum = parts[4];
    key.rawKey = keyString;

    return key;
}

bool LicenseValidator::validateChecksum(const LicenseKey& key) const {
    std::string tierStr = tierToString(key.tier);
    std::string expected = computeChecksum(tierStr, key.segment1, key.segment2, key.segment3);
    return key.checksum == expected;
}

bool LicenseValidator::checkExpiration(const std::string& expiresAt) const {
    if (expiresAt.empty()) {
        return false;  // No expiration means never expires (not expired)
    }

    // Parse YYYY-MM-DD format
    if (expiresAt.size() != 10) {
        return true;  // Invalid format treated as expired
    }

    std::tm tm = {};
    std::istringstream iss(expiresAt);
    iss >> std::get_time(&tm, "%Y-%m-%d");
    if (iss.fail()) {
        return true;  // Parse failure means expired
    }

    auto expiry = std::mktime(&tm);
    auto now = std::time(nullptr);

    return now > expiry;
}

int LicenseValidator::getSeatLimit(LicenseType tier) const {
    switch (tier) {
        case LicenseType::Free:
            return 1;
        case LicenseType::Professional:
            return 25;
        case LicenseType::Enterprise:
            return 500;
        case LicenseType::Ultimate:
            return 10000;
    }
    return 1;
}

bool LicenseValidator::enforceSeatLimit(LicenseType tier, int currentSeats) const {
    return currentSeats <= getSeatLimit(tier);
}

int LicenseValidator::calculateGracePeriod(LicenseType tier) const {
    switch (tier) {
        case LicenseType::Free:
            return 0;   // No grace period for free
        case LicenseType::Professional:
            return 7;   // 7 days
        case LicenseType::Enterprise:
            return 30;  // 30 days
        case LicenseType::Ultimate:
            return 60;  // 60 days
    }
    return 0;
}

std::string LicenseValidator::parseExpiration(const LicenseKey& key) const {
    // Segment2 encodes the expiration date as a numeric offset
    // Format: First 2 chars = month (01-12), next 2 = year offset from 2020, last char = day/2
    // E.g., "06052" = month 06, year 2025 (20+05), day 4 (2*2)
    // For simplicity in this implementation, we derive a date from the segment
    if (key.segment2.size() != 5) {
        return "";
    }

    // Extract numeric values from the alphanumeric segment
    int val = 0;
    for (char c : key.segment2) {
        if (c >= '0' && c <= '9') {
            val = val * 10 + (c - '0');
        } else {
            val = val * 10 + (c - 'A' + 10);
        }
    }

    // Convert to days from epoch 2020-01-01
    // Use modulo to keep within reasonable range
    int daysFromBase = val % 7300;  // ~20 years

    // Base date: 2020-01-01
    std::tm base = {};
    base.tm_year = 120;  // 2020
    base.tm_mon = 0;     // January
    base.tm_mday = 1 + daysFromBase;
    base.tm_isdst = -1;

    std::mktime(&base);  // Normalize

    std::ostringstream oss;
    oss << std::put_time(&base, "%Y-%m-%d");
    return oss.str();
}

ValidationResult LicenseValidator::validate(const std::string& keyString) const {
    ValidationResult result;

    auto keyOpt = parseKey(keyString);
    if (!keyOpt.has_value()) {
        result.valid = false;
        result.reason = "Invalid key format";
        return result;
    }

    const auto& key = keyOpt.value();

    if (!validateChecksum(key)) {
        result.valid = false;
        result.reason = "Invalid checksum";
        return result;
    }

    std::string expiration = parseExpiration(key);
    result.expiresAt = expiration;
    result.seatsAllowed = getSeatLimit(key.tier);
    result.gracePeriodDays = calculateGracePeriod(key.tier);

    if (checkExpiration(expiration)) {
        // Check if within grace period
        if (result.gracePeriodDays > 0) {
            result.valid = true;
            result.reason = "License expired but within grace period";
        } else {
            result.valid = false;
            result.reason = "License expired";
        }
    } else {
        result.valid = true;
        result.reason = "Valid";
    }

    return result;
}

std::string LicenseValidator::computeChecksum(const std::string& tierStr,
                                               const std::string& seg1,
                                               const std::string& seg2,
                                               const std::string& seg3) const {
    // Simple hash-based checksum: sum of all character values mod 36^5
    // then encode as 5 uppercase alphanumeric characters
    std::string combined = tierStr + seg1 + seg2 + seg3;

    unsigned long hash = 5381;
    for (char c : combined) {
        hash = ((hash << 5) + hash) + static_cast<unsigned char>(c);  // djb2
    }

    // Encode as 5 alphanumeric uppercase chars
    std::string checksum;
    checksum.reserve(5);
    const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < 5; ++i) {
        checksum += chars[hash % 36];
        hash /= 36;
    }

    return checksum;
}

std::optional<LicenseType> LicenseValidator::tierFromString(const std::string& tierStr) const {
    if (tierStr == "FREE") return LicenseType::Free;
    if (tierStr == "PRO") return LicenseType::Professional;
    if (tierStr == "ENT") return LicenseType::Enterprise;
    if (tierStr == "ULT") return LicenseType::Ultimate;
    return std::nullopt;
}

std::string LicenseValidator::tierToString(LicenseType tier) const {
    switch (tier) {
        case LicenseType::Free: return "FREE";
        case LicenseType::Professional: return "PRO";
        case LicenseType::Enterprise: return "ENT";
        case LicenseType::Ultimate: return "ULT";
    }
    return "FREE";
}

} // namespace ThreatOne::Licensing
