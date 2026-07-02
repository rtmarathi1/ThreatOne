#include "compliance/ComplianceFramework.h"
#include <sstream>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace ThreatOne::Compliance {

ComplianceFramework::ComplianceFramework()
    : logger_("ComplianceFramework") {
    initializeFrameworks();
    logger_.info("ComplianceFramework initialized with {} frameworks", frameworks_.size());
}

std::string ComplianceFramework::frameworkToString(Framework type) {
    switch (type) {
        case Framework::NIST: return "NIST CSF";
        case Framework::ISO27001: return "ISO 27001";
        case Framework::SOC2: return "SOC 2";
        case Framework::HIPAA: return "HIPAA";
        case Framework::PCI_DSS: return "PCI-DSS";
        case Framework::GDPR: return "GDPR";
        case Framework::CIS: return "CIS Benchmarks";
    }
    return "Unknown";
}

std::optional<FrameworkDefinition> ComplianceFramework::getFramework(Framework type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = frameworks_.find(type);
    if (it == frameworks_.end()) return std::nullopt;
    return it->second;
}

std::vector<FrameworkDefinition> ComplianceFramework::getAllFrameworks() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<FrameworkDefinition> result;
    result.reserve(frameworks_.size());
    for (const auto& [key, def] : frameworks_) {
        result.push_back(def);
    }
    return result;
}

std::vector<FrameworkInfo> ComplianceFramework::getFrameworkInfos() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<FrameworkInfo> infos;
    for (const auto& [key, def] : frameworks_) {
        FrameworkInfo info;
        info.type = def.type;
        info.name = def.name;
        info.version = def.version;
        uint32_t total = 0;
        uint32_t implemented = 0;
        for (const auto& cat : def.categories) {
            for (const auto& ctrl : cat.controls) {
                total++;
                if (ctrl.implemented) implemented++;
            }
        }
        info.totalControls = total;
        info.implementedControls = implemented;
        infos.push_back(info);
    }
    return infos;
}

std::vector<ControlInfo> ComplianceFramework::getControls(Framework type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ControlInfo> controls;
    auto it = frameworks_.find(type);
    if (it == frameworks_.end()) return controls;
    for (const auto& cat : it->second.categories) {
        for (const auto& ctrl : cat.controls) {
            controls.push_back(ctrl);
        }
    }
    return controls;
}

std::vector<ControlInfo> ComplianceFramework::getControlsByCategory(
    Framework type, const std::string& categoryId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ControlInfo> controls;
    auto it = frameworks_.find(type);
    if (it == frameworks_.end()) return controls;
    for (const auto& cat : it->second.categories) {
        if (cat.id == categoryId) {
            return cat.controls;
        }
    }
    return controls;
}

std::optional<ControlInfo> ComplianceFramework::getControl(
    Framework type, const std::string& controlId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = frameworks_.find(type);
    if (it == frameworks_.end()) return std::nullopt;
    for (const auto& cat : it->second.categories) {
        for (const auto& ctrl : cat.controls) {
            if (ctrl.id == controlId) return ctrl;
        }
    }
    return std::nullopt;
}

std::vector<ControlCategory> ComplianceFramework::getCategories(Framework type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = frameworks_.find(type);
    if (it == frameworks_.end()) return {};
    return it->second.categories;
}

void ComplianceFramework::initializeFrameworks() {
    addNISTFramework();
    addISO27001Framework();
    addSOC2Framework();
    addHIPAAFramework();
    addPCIDSSFramework();
    addGDPRFramework();
    addCISFramework();
}

void ComplianceFramework::addNISTFramework() {
    FrameworkDefinition fw;
    fw.type = Framework::NIST;
    fw.name = "NIST CSF";
    fw.version = "1.1";

    std::vector<std::pair<std::string, std::string>> cats = {
        {"ID", "Identify"}, {"PR", "Protect"}, {"DE", "Detect"},
        {"RS", "Respond"}, {"RC", "Recover"}
    };
    for (const auto& [id, name] : cats) {
        ControlCategory cat;
        cat.id = "NIST-" + id;
        cat.name = name;
        cat.description = name + " function of NIST CSF";
        for (int i = 1; i <= 5; i++) {
            ControlInfo ctrl;
            ctrl.id = "NIST-" + id + "-" + std::to_string(i);
            ctrl.name = name + " Control " + std::to_string(i);
            ctrl.description = "Control for " + name + " category item " + std::to_string(i);
            ctrl.framework = Framework::NIST;
            ctrl.categoryId = cat.id;
            ctrl.status = "active";
            ctrl.implemented = (i <= 3);
            cat.controls.push_back(ctrl);
        }
        fw.categories.push_back(cat);
    }
    frameworks_[Framework::NIST] = fw;
}

void ComplianceFramework::addISO27001Framework() {
    FrameworkDefinition fw;
    fw.type = Framework::ISO27001;
    fw.name = "ISO 27001";
    fw.version = "2022";

    std::vector<std::pair<std::string, std::string>> cats = {
        {"A5", "Information Security Policies"},
        {"A6", "Organization of Information Security"},
        {"A7", "Human Resource Security"},
        {"A8", "Asset Management"},
        {"A9", "Access Control"},
        {"A10", "Cryptography"}
    };
    for (const auto& [id, name] : cats) {
        ControlCategory cat;
        cat.id = "ISO-" + id;
        cat.name = name;
        cat.description = name + " domain of ISO 27001";
        for (int i = 1; i <= 4; i++) {
            ControlInfo ctrl;
            ctrl.id = "ISO-" + id + "." + std::to_string(i);
            ctrl.name = name + " Control " + std::to_string(i);
            ctrl.description = "Control for " + name + " item " + std::to_string(i);
            ctrl.framework = Framework::ISO27001;
            ctrl.categoryId = cat.id;
            ctrl.status = "active";
            ctrl.implemented = (i <= 2);
            cat.controls.push_back(ctrl);
        }
        fw.categories.push_back(cat);
    }
    frameworks_[Framework::ISO27001] = fw;
}

void ComplianceFramework::addSOC2Framework() {
    FrameworkDefinition fw;
    fw.type = Framework::SOC2;
    fw.name = "SOC 2";
    fw.version = "2017";

    std::vector<std::pair<std::string, std::string>> cats = {
        {"CC1", "Control Environment"},
        {"CC2", "Communication and Information"},
        {"CC3", "Risk Assessment"},
        {"CC4", "Monitoring Activities"},
        {"CC5", "Control Activities"},
        {"CC6", "Logical and Physical Access"},
        {"CC7", "System Operations"}
    };
    for (const auto& [id, name] : cats) {
        ControlCategory cat;
        cat.id = "SOC2-" + id;
        cat.name = name;
        cat.description = name + " criteria of SOC 2";
        for (int i = 1; i <= 3; i++) {
            ControlInfo ctrl;
            ctrl.id = "SOC2-" + id + "." + std::to_string(i);
            ctrl.name = name + " Control " + std::to_string(i);
            ctrl.description = "Control for " + name + " item " + std::to_string(i);
            ctrl.framework = Framework::SOC2;
            ctrl.categoryId = cat.id;
            ctrl.status = "active";
            ctrl.implemented = (i <= 2);
            cat.controls.push_back(ctrl);
        }
        fw.categories.push_back(cat);
    }
    frameworks_[Framework::SOC2] = fw;
}

void ComplianceFramework::addHIPAAFramework() {
    FrameworkDefinition fw;
    fw.type = Framework::HIPAA;
    fw.name = "HIPAA";
    fw.version = "2013";

    std::vector<std::pair<std::string, std::string>> cats = {
        {"ADM", "Administrative Safeguards"},
        {"PHY", "Physical Safeguards"},
        {"TEC", "Technical Safeguards"},
        {"ORG", "Organizational Requirements"},
        {"POL", "Policies and Procedures"}
    };
    for (const auto& [id, name] : cats) {
        ControlCategory cat;
        cat.id = "HIPAA-" + id;
        cat.name = name;
        cat.description = name + " section of HIPAA";
        for (int i = 1; i <= 4; i++) {
            ControlInfo ctrl;
            ctrl.id = "HIPAA-" + id + "-" + std::to_string(i);
            ctrl.name = name + " Control " + std::to_string(i);
            ctrl.description = "Control for " + name + " item " + std::to_string(i);
            ctrl.framework = Framework::HIPAA;
            ctrl.categoryId = cat.id;
            ctrl.status = "active";
            ctrl.implemented = (i <= 2);
            cat.controls.push_back(ctrl);
        }
        fw.categories.push_back(cat);
    }
    frameworks_[Framework::HIPAA] = fw;
}

void ComplianceFramework::addPCIDSSFramework() {
    FrameworkDefinition fw;
    fw.type = Framework::PCI_DSS;
    fw.name = "PCI-DSS";
    fw.version = "4.0";

    std::vector<std::pair<std::string, std::string>> cats = {
        {"R1", "Network Security Controls"},
        {"R2", "Secure Configuration"},
        {"R3", "Protect Account Data"},
        {"R4", "Encryption in Transit"},
        {"R5", "Malware Protection"},
        {"R6", "Secure Development"}
    };
    for (const auto& [id, name] : cats) {
        ControlCategory cat;
        cat.id = "PCI-" + id;
        cat.name = name;
        cat.description = name + " requirement of PCI-DSS";
        for (int i = 1; i <= 4; i++) {
            ControlInfo ctrl;
            ctrl.id = "PCI-" + id + "." + std::to_string(i);
            ctrl.name = name + " Control " + std::to_string(i);
            ctrl.description = "Control for " + name + " item " + std::to_string(i);
            ctrl.framework = Framework::PCI_DSS;
            ctrl.categoryId = cat.id;
            ctrl.status = "active";
            ctrl.implemented = (i <= 2);
            cat.controls.push_back(ctrl);
        }
        fw.categories.push_back(cat);
    }
    frameworks_[Framework::PCI_DSS] = fw;
}

void ComplianceFramework::addGDPRFramework() {
    FrameworkDefinition fw;
    fw.type = Framework::GDPR;
    fw.name = "GDPR";
    fw.version = "2018";

    std::vector<std::pair<std::string, std::string>> cats = {
        {"ART5", "Data Processing Principles"},
        {"ART6", "Lawfulness of Processing"},
        {"ART25", "Data Protection by Design"},
        {"ART30", "Records of Processing"},
        {"ART32", "Security of Processing"},
        {"ART33", "Breach Notification"}
    };
    for (const auto& [id, name] : cats) {
        ControlCategory cat;
        cat.id = "GDPR-" + id;
        cat.name = name;
        cat.description = name + " article of GDPR";
        for (int i = 1; i <= 3; i++) {
            ControlInfo ctrl;
            ctrl.id = "GDPR-" + id + "." + std::to_string(i);
            ctrl.name = name + " Control " + std::to_string(i);
            ctrl.description = "Control for " + name + " item " + std::to_string(i);
            ctrl.framework = Framework::GDPR;
            ctrl.categoryId = cat.id;
            ctrl.status = "active";
            ctrl.implemented = (i <= 2);
            cat.controls.push_back(ctrl);
        }
        fw.categories.push_back(cat);
    }
    frameworks_[Framework::GDPR] = fw;
}

void ComplianceFramework::addCISFramework() {
    FrameworkDefinition fw;
    fw.type = Framework::CIS;
    fw.name = "CIS Benchmarks";
    fw.version = "8.0";

    std::vector<std::pair<std::string, std::string>> cats = {
        {"CIS1", "Inventory and Control of Enterprise Assets"},
        {"CIS2", "Inventory and Control of Software Assets"},
        {"CIS3", "Data Protection"},
        {"CIS4", "Secure Configuration"},
        {"CIS5", "Account Management"},
        {"CIS6", "Access Control Management"},
        {"CIS7", "Continuous Vulnerability Management"}
    };
    for (const auto& [id, name] : cats) {
        ControlCategory cat;
        cat.id = id;
        cat.name = name;
        cat.description = name + " benchmark of CIS";
        for (int i = 1; i <= 4; i++) {
            ControlInfo ctrl;
            ctrl.id = id + "." + std::to_string(i);
            ctrl.name = name + " Control " + std::to_string(i);
            ctrl.description = "Control for " + name + " item " + std::to_string(i);
            ctrl.framework = Framework::CIS;
            ctrl.categoryId = cat.id;
            ctrl.status = "active";
            ctrl.implemented = (i <= 2);
            cat.controls.push_back(ctrl);
        }
        fw.categories.push_back(cat);
    }
    frameworks_[Framework::CIS] = fw;
}

} // namespace ThreatOne::Compliance
