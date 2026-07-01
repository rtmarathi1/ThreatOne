#include "ai/RecommendationEngine.h"

#include <algorithm>

namespace ThreatOne::AI {

RecommendationEngine::RecommendationEngine()
    : logger_(Core::Logger::instance().getModuleLogger("RecommendationEngine")) {
    logger_.info("RecommendationEngine initialized");
}

std::vector<SecurityRecommendation> RecommendationEngine::generateRecommendations(
    const RiskPosture& posture) const {

    logger_.debug("Generating recommendations for risk={}, vulns={}, threats={}, gaps={}",
                  posture.overallRisk, posture.openVulnerabilities,
                  posture.activeThreats, posture.configGaps.size());

    std::vector<SecurityRecommendation> recommendations;

    // Generate threat-based recommendations
    if (posture.activeThreats > 0) {
        auto threatRecs = generateThreatRecommendations(posture.activeThreats);
        recommendations.insert(recommendations.end(), threatRecs.begin(), threatRecs.end());
    }

    // Generate vulnerability-based recommendations
    if (posture.openVulnerabilities > 0) {
        auto vulnRecs = generateVulnerabilityRecommendations(posture.openVulnerabilities);
        recommendations.insert(recommendations.end(), vulnRecs.begin(), vulnRecs.end());
    }

    // Generate config-gap recommendations
    if (!posture.configGaps.empty()) {
        auto configRecs = generateConfigRecommendations(posture.configGaps);
        recommendations.insert(recommendations.end(), configRecs.begin(), configRecs.end());
    }

    // Generate overall risk recommendations
    auto riskRecs = generateRiskRecommendations(posture.overallRisk);
    recommendations.insert(recommendations.end(), riskRecs.begin(), riskRecs.end());

    return prioritize(std::move(recommendations));
}

std::vector<SecurityRecommendation> RecommendationEngine::prioritize(
    std::vector<SecurityRecommendation> recommendations) const {

    // Sort by priority (lower number = higher priority), then by impact
    std::sort(recommendations.begin(), recommendations.end(),
              [](const SecurityRecommendation& a, const SecurityRecommendation& b) {
                  if (a.priority != b.priority) {
                      return a.priority < b.priority;
                  }
                  // "high" > "medium" > "low" for impact
                  auto impactScore = [](const std::string& impact) -> int {
                      if (impact == "high") return 3;
                      if (impact == "medium") return 2;
                      return 1;
                  };
                  return impactScore(a.impact) > impactScore(b.impact);
              });

    return recommendations;
}

std::vector<SecurityRecommendation> RecommendationEngine::getTopN(
    int n, const RiskPosture& posture) const {

    auto all = generateRecommendations(posture);

    if (static_cast<int>(all.size()) <= n) {
        return all;
    }

    return std::vector<SecurityRecommendation>(all.begin(), all.begin() + n);
}

std::vector<SecurityRecommendation> RecommendationEngine::generateThreatRecommendations(
    int activeThreats) const {

    std::vector<SecurityRecommendation> recs;

    if (activeThreats >= 5) {
        recs.push_back({
            "THR-001",
            "Isolate Compromised Systems",
            "Multiple active threats detected. Immediately isolate affected systems from the network to prevent lateral movement.",
            1,
            "threat_response",
            "low",
            "high"
        });
    }

    if (activeThreats >= 1) {
        recs.push_back({
            "THR-002",
            "Quarantine Detected Threats",
            "Active threats require immediate quarantine. Move detected malicious files to secure containment.",
            1,
            "threat_response",
            "low",
            "high"
        });
        recs.push_back({
            "THR-003",
            "Run Full System Scan",
            "Perform comprehensive scan of all endpoints to identify additional compromise indicators.",
            2,
            "threat_response",
            "medium",
            "high"
        });
    }

    if (activeThreats >= 3) {
        recs.push_back({
            "THR-004",
            "Activate Incident Response Plan",
            "Multiple threats indicate a potential coordinated attack. Activate formal incident response procedures.",
            1,
            "incident_response",
            "medium",
            "high"
        });
    }

    return recs;
}

std::vector<SecurityRecommendation> RecommendationEngine::generateVulnerabilityRecommendations(
    int openVulnerabilities) const {

    std::vector<SecurityRecommendation> recs;

    if (openVulnerabilities >= 10) {
        recs.push_back({
            "VUL-001",
            "Emergency Patching Required",
            "Critical number of open vulnerabilities detected. Prioritize patching of high-severity vulnerabilities immediately.",
            1,
            "vulnerability_management",
            "high",
            "high"
        });
    } else if (openVulnerabilities >= 5) {
        recs.push_back({
            "VUL-002",
            "Schedule Patch Deployment",
            "Multiple vulnerabilities detected. Schedule patch deployment within the next maintenance window.",
            2,
            "vulnerability_management",
            "medium",
            "high"
        });
    } else {
        recs.push_back({
            "VUL-003",
            "Review Open Vulnerabilities",
            "Open vulnerabilities detected. Review and prioritize for remediation.",
            3,
            "vulnerability_management",
            "low",
            "medium"
        });
    }

    recs.push_back({
        "VUL-004",
        "Enable Automated Patch Management",
        "Configure automated patching for non-critical systems to reduce vulnerability exposure window.",
        3,
        "vulnerability_management",
        "medium",
        "medium"
    });

    return recs;
}

std::vector<SecurityRecommendation> RecommendationEngine::generateConfigRecommendations(
    const std::vector<std::string>& configGaps) const {

    std::vector<SecurityRecommendation> recs;

    for (const auto& gap : configGaps) {
        if (gap == "mfa_disabled" || gap == "no_mfa") {
            recs.push_back({
                "CFG-001",
                "Enable Multi-Factor Authentication",
                "MFA is not enabled. Enable multi-factor authentication for all user accounts to prevent unauthorized access.",
                2,
                "configuration",
                "medium",
                "high"
            });
        } else if (gap == "weak_passwords" || gap == "password_policy") {
            recs.push_back({
                "CFG-002",
                "Strengthen Password Policy",
                "Weak password policy detected. Enforce minimum 12 characters, complexity requirements, and regular rotation.",
                2,
                "configuration",
                "low",
                "medium"
            });
        } else if (gap == "open_ports" || gap == "unnecessary_services") {
            recs.push_back({
                "CFG-003",
                "Close Unnecessary Ports and Services",
                "Unnecessary network services or ports are exposed. Close all non-essential ports and disable unused services.",
                2,
                "configuration",
                "low",
                "high"
            });
        } else if (gap == "no_encryption" || gap == "weak_encryption") {
            recs.push_back({
                "CFG-004",
                "Enable Data Encryption",
                "Data encryption is missing or weak. Enable TLS 1.3 for data in transit and AES-256 for data at rest.",
                2,
                "configuration",
                "medium",
                "high"
            });
        } else if (gap == "outdated_signatures" || gap == "stale_definitions") {
            recs.push_back({
                "CFG-005",
                "Update Security Signatures",
                "Security signatures are outdated. Update antivirus and IDS/IPS signatures to latest available versions.",
                2,
                "configuration",
                "low",
                "medium"
            });
        } else {
            recs.push_back({
                "CFG-099",
                "Address Configuration Gap: " + gap,
                "A configuration gap has been identified: " + gap + ". Review and remediate according to security best practices.",
                3,
                "configuration",
                "medium",
                "medium"
            });
        }
    }

    return recs;
}

std::vector<SecurityRecommendation> RecommendationEngine::generateRiskRecommendations(
    double overallRisk) const {

    std::vector<SecurityRecommendation> recs;

    if (overallRisk >= 80.0) {
        recs.push_back({
            "RSK-001",
            "Critical Risk Level - Immediate Action Required",
            "Overall risk score is critical. Review all security controls and consider activating business continuity procedures.",
            1,
            "risk_management",
            "high",
            "high"
        });
    } else if (overallRisk >= 60.0) {
        recs.push_back({
            "RSK-002",
            "Elevated Risk - Increase Monitoring",
            "Risk level is elevated. Increase monitoring frequency and review security alerts more frequently.",
            2,
            "risk_management",
            "low",
            "medium"
        });
    } else if (overallRisk >= 40.0) {
        recs.push_back({
            "RSK-003",
            "Moderate Risk - Schedule Review",
            "Risk is moderate. Schedule a security posture review to identify improvement opportunities.",
            4,
            "risk_management",
            "low",
            "low"
        });
    }

    return recs;
}

} // namespace ThreatOne::AI
