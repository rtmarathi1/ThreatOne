#include "edr/PersistenceDetection.h"

#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

namespace ThreatOne::EDR {

PersistenceDetection::PersistenceDetection()
    : logger_(Core::Logger::instance().getModuleLogger("PersistenceDetection"))
{
    logger_.info("PersistenceDetection initialized");
}

std::vector<PersistenceIndicator> PersistenceDetection::scanForPersistence() const {
    std::lock_guard lock(mutex_);
    std::vector<PersistenceIndicator> results;

    auto cronResults = checkCronJobs();
    results.insert(results.end(), cronResults.begin(), cronResults.end());

    auto systemdResults = checkSystemdUnits();
    results.insert(results.end(), systemdResults.begin(), systemdResults.end());

    auto initResults = checkInitScripts();
    results.insert(results.end(), initResults.begin(), initResults.end());

    auto shellResults = checkShellProfiles();
    results.insert(results.end(), shellResults.begin(), shellResults.end());

    auto ldResults = checkLdPreload();
    results.insert(results.end(), ldResults.begin(), ldResults.end());

    auto rcResults = checkRcLocal();
    results.insert(results.end(), rcResults.begin(), rcResults.end());

    return results;
}

std::vector<PersistenceIndicator> PersistenceDetection::checkCronJobs() const {
    std::vector<PersistenceIndicator> results;
    std::vector<std::string> cronPaths = {
        basePath_ + "/etc/cron.d",
        basePath_ + "/var/spool/cron",
        basePath_ + "/etc/crontab"
    };

    for (const auto& path : cronPaths) {
        if (pathExists(path)) {
            if (fs::is_directory(path)) {
                try {
                    for (const auto& entry : fs::directory_iterator(path)) {
                        PersistenceIndicator indicator;
                        indicator.type = "cron_job";
                        indicator.location = entry.path().string();
                        indicator.description = "Cron job found: " + entry.path().filename().string();
                        indicator.severity = "medium";
                        results.push_back(indicator);
                    }
                } catch (...) {
                    // Skip inaccessible directories
                }
            } else {
                std::string content = readFileContents(path);
                if (!content.empty()) {
                    PersistenceIndicator indicator;
                    indicator.type = "cron_job";
                    indicator.location = path;
                    indicator.description = "Crontab file found with content";
                    indicator.severity = "medium";
                    results.push_back(indicator);
                }
            }
        }
    }

    return results;
}

std::vector<PersistenceIndicator> PersistenceDetection::checkSystemdUnits() const {
    std::vector<PersistenceIndicator> results;
    std::string systemdPath = basePath_ + "/etc/systemd/system";

    if (pathExists(systemdPath) && fs::is_directory(systemdPath)) {
        try {
            for (const auto& entry : fs::directory_iterator(systemdPath)) {
                if (entry.path().extension() == ".service") {
                    PersistenceIndicator indicator;
                    indicator.type = "systemd_unit";
                    indicator.location = entry.path().string();
                    indicator.description = "Systemd service unit: " + entry.path().filename().string();
                    indicator.severity = "medium";
                    results.push_back(indicator);
                }
            }
        } catch (...) {
            // Skip inaccessible directories
        }
    }

    return results;
}

std::vector<PersistenceIndicator> PersistenceDetection::checkInitScripts() const {
    std::vector<PersistenceIndicator> results;
    std::string initPath = basePath_ + "/etc/init.d";

    if (pathExists(initPath) && fs::is_directory(initPath)) {
        try {
            for (const auto& entry : fs::directory_iterator(initPath)) {
                if (entry.is_regular_file()) {
                    PersistenceIndicator indicator;
                    indicator.type = "init_script";
                    indicator.location = entry.path().string();
                    indicator.description = "Init script: " + entry.path().filename().string();
                    indicator.severity = "medium";
                    results.push_back(indicator);
                }
            }
        } catch (...) {
            // Skip inaccessible directories
        }
    }

    return results;
}

std::vector<PersistenceIndicator> PersistenceDetection::checkShellProfiles() const {
    std::vector<PersistenceIndicator> results;
    std::vector<std::string> profilePaths = {
        basePath_ + "/.bashrc",
        basePath_ + "/.profile",
        basePath_ + "/.bash_profile",
        basePath_ + "/.zshrc"
    };

    for (const auto& path : profilePaths) {
        if (pathExists(path)) {
            PersistenceIndicator indicator;
            indicator.type = "shell_profile";
            indicator.location = path;
            indicator.description = "Shell profile file found: " + fs::path(path).filename().string();
            indicator.severity = "low";
            results.push_back(indicator);
        }
    }

    return results;
}

std::vector<PersistenceIndicator> PersistenceDetection::checkLdPreload() const {
    std::vector<PersistenceIndicator> results;
    std::string ldPreloadPath = basePath_ + "/etc/ld.so.preload";

    if (pathExists(ldPreloadPath)) {
        std::string content = readFileContents(ldPreloadPath);
        if (!content.empty()) {
            PersistenceIndicator indicator;
            indicator.type = "ld_preload";
            indicator.location = ldPreloadPath;
            indicator.description = "LD_PRELOAD configuration found - potential library injection";
            indicator.severity = "high";
            results.push_back(indicator);
        }
    }

    return results;
}

std::vector<PersistenceIndicator> PersistenceDetection::checkRcLocal() const {
    std::vector<PersistenceIndicator> results;
    std::string rcLocalPath = basePath_ + "/etc/rc.local";

    if (pathExists(rcLocalPath)) {
        std::string content = readFileContents(rcLocalPath);
        if (!content.empty()) {
            PersistenceIndicator indicator;
            indicator.type = "rc_local";
            indicator.location = rcLocalPath;
            indicator.description = "rc.local file found with startup commands";
            indicator.severity = "medium";
            results.push_back(indicator);
        }
    }

    return results;
}

void PersistenceDetection::setBasePath(const std::string& basePath) {
    std::lock_guard lock(mutex_);
    basePath_ = basePath;
}

bool PersistenceDetection::pathExists(const std::string& path) const {
    try {
        return fs::exists(path);
    } catch (...) {
        return false;
    }
}

std::string PersistenceDetection::readFileContents(const std::string& path) const {
    try {
        std::ifstream file(path);
        if (!file.is_open()) return "";
        std::stringstream ss;
        ss << file.rdbuf();
        return ss.str();
    } catch (...) {
        return "";
    }
}

} // namespace ThreatOne::EDR
