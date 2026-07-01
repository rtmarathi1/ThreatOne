#include "sandbox/SandboxEngine.h"

#include <algorithm>
#include <chrono>
#include <sstream>

namespace ThreatOne::Sandbox {

SandboxEngine::SandboxEngine()
    : logger_("SandboxEngine") {
    initDefaultProfiles();
    logger_.info("Sandbox Engine initialized");
}

void SandboxEngine::initDefaultProfiles() {
    SandboxProfile quick;
    quick.id = "PROF-DEFAULT-QUICK";
    quick.name = "Quick Analysis";
    quick.type = ProfileType::Quick;
    quick.timeoutSeconds = 30;
    quick.networkSimulation = false;
    quick.recordRegistry = true;
    quick.recordFilesystem = true;
    quick.recordNetwork = false;
    profiles_[quick.id] = quick;

    SandboxProfile deep;
    deep.id = "PROF-DEFAULT-DEEP";
    deep.name = "Deep Analysis";
    deep.type = ProfileType::Deep;
    deep.timeoutSeconds = 300;
    deep.networkSimulation = true;
    deep.recordRegistry = true;
    deep.recordFilesystem = true;
    deep.recordNetwork = true;
    profiles_[deep.id] = deep;

    SandboxProfile custom;
    custom.id = "PROF-DEFAULT-CUSTOM";
    custom.name = "Custom Analysis";
    custom.type = ProfileType::Custom;
    custom.timeoutSeconds = 120;
    custom.networkSimulation = true;
    custom.recordRegistry = true;
    custom.recordFilesystem = true;
    custom.recordNetwork = true;
    profiles_[custom.id] = custom;
}

std::string SandboxEngine::generateSampleId() {
    std::ostringstream oss;
    oss << "SAMPLE-" << nextSampleId_;
    ++nextSampleId_;
    return oss.str();
}

std::string SandboxEngine::generateJobId() {
    std::ostringstream oss;
    oss << "JOB-" << nextJobId_;
    ++nextJobId_;
    return oss.str();
}

std::string SandboxEngine::generateProfileId() {
    std::ostringstream oss;
    oss << "PROF-" << nextProfileId_;
    ++nextProfileId_;
    return oss.str();
}

std::string SandboxEngine::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << time;
    return oss.str();
}

SandboxVerdict SandboxEngine::computeVerdict(const std::vector<std::string>& behaviors) const {
    if (behaviors.empty()) {
        return SandboxVerdict::Clean;
    }
    if (behaviors.size() <= 2) {
        return SandboxVerdict::Suspicious;
    }
    return SandboxVerdict::Malicious;
}

std::vector<IOCInfo> SandboxEngine::extractIOCs(const BehaviorReport& report) const {
    std::vector<IOCInfo> iocs;

    // Extract IP IOCs from network connections
    for (const auto& conn : report.networkConnections) {
        IOCInfo ioc;
        ioc.type = "ip";
        ioc.value = conn;
        ioc.description = "Network connection observed during detonation";
        ioc.confidence = "high";
        iocs.push_back(ioc);
    }

    // Extract file hash IOCs from dropped files
    for (const auto& file : report.droppedFiles) {
        IOCInfo ioc;
        ioc.type = "file_hash";
        ioc.value = file;
        ioc.description = "File dropped during detonation";
        ioc.confidence = "high";
        iocs.push_back(ioc);
    }

    // Extract registry IOCs
    for (const auto& reg : report.registryChanges) {
        IOCInfo ioc;
        ioc.type = "registry";
        ioc.value = reg;
        ioc.description = "Registry modification during detonation";
        ioc.confidence = "medium";
        iocs.push_back(ioc);
    }

    // Extract process IOCs
    for (const auto& proc : report.processesCreated) {
        IOCInfo ioc;
        ioc.type = "process";
        ioc.value = proc;
        ioc.description = "Process created during detonation";
        ioc.confidence = "medium";
        iocs.push_back(ioc);
    }

    return iocs;
}

std::string SandboxEngine::submitSample(const std::string& filePath) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (filePath.empty()) {
        logger_.error("Cannot submit sample: empty file path");
        return "";
    }

    std::string sampleId = generateSampleId();
    std::string jobId = generateJobId();

    // Create default detonation config
    DetonationConfig config;
    config.samplePath = filePath;
    config.profileId = "PROF-DEFAULT-QUICK";
    config.priority = DetonationPriority::Normal;

    // Create detonation job
    DetonationJob job;
    job.id = jobId;
    job.config = config;
    job.status = DetonationStatus::Queued;
    job.submittedAt = getCurrentTimestamp();

    jobs_[jobId] = job;
    sampleToJob_[sampleId] = jobId;

    // Initialize empty behavior report
    BehaviorReport report;
    report.sampleId = sampleId;
    reports_[sampleId] = report;

    logger_.info("Submitted sample: {} -> {} (job {})", filePath, sampleId, jobId);
    return sampleId;
}

std::string SandboxEngine::submitWithProfile(const DetonationConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (config.samplePath.empty()) {
        logger_.error("Cannot submit: empty sample path");
        return "";
    }

    // Validate profile exists
    if (profiles_.find(config.profileId) == profiles_.end()) {
        logger_.error("Cannot submit: profile {} not found", config.profileId);
        return "";
    }

    std::string jobId = generateJobId();
    std::string sampleId = generateSampleId();

    DetonationJob job;
    job.id = jobId;
    job.config = config;
    job.status = DetonationStatus::Queued;
    job.submittedAt = getCurrentTimestamp();

    jobs_[jobId] = job;
    sampleToJob_[sampleId] = jobId;

    // Initialize empty behavior report
    BehaviorReport report;
    report.sampleId = sampleId;
    reports_[sampleId] = report;

    logger_.info("Submitted sample with profile {}: {} -> job {}", config.profileId, config.samplePath, jobId);
    return jobId;
}

std::optional<DetonationStatus> SandboxEngine::getDetonationStatus(const std::string& jobId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = jobs_.find(jobId);
    if (it == jobs_.end()) {
        return std::nullopt;
    }
    return it->second.status;
}

bool SandboxEngine::cancelDetonation(const std::string& jobId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = jobs_.find(jobId);
    if (it == jobs_.end()) {
        logger_.error("Cannot cancel: job {} not found", jobId);
        return false;
    }

    if (it->second.status == DetonationStatus::Completed ||
        it->second.status == DetonationStatus::Failed) {
        logger_.warn("Cannot cancel job {}: already in terminal state", jobId);
        return false;
    }

    it->second.status = DetonationStatus::Failed;
    it->second.completedAt = getCurrentTimestamp();
    logger_.info("Cancelled detonation job: {}", jobId);
    return true;
}

AnalysisResult SandboxEngine::getAnalysis(const std::string& sampleId) {
    std::lock_guard<std::mutex> lock(mutex_);

    AnalysisResult result;
    result.id = sampleId;
    result.timestamp = getCurrentTimestamp();

    auto reportIt = reports_.find(sampleId);
    if (reportIt == reports_.end()) {
        result.verdict = "unknown";
        result.score = 0.0;
        logger_.warn("No analysis found for sample: {}", sampleId);
        return result;
    }

    // Aggregate all behaviors
    const auto& report = reportIt->second;
    std::vector<std::string> allBehaviors;
    allBehaviors.insert(allBehaviors.end(), report.processesCreated.begin(), report.processesCreated.end());
    allBehaviors.insert(allBehaviors.end(), report.filesModified.begin(), report.filesModified.end());
    allBehaviors.insert(allBehaviors.end(), report.registryChanges.begin(), report.registryChanges.end());
    allBehaviors.insert(allBehaviors.end(), report.networkConnections.begin(), report.networkConnections.end());
    allBehaviors.insert(allBehaviors.end(), report.droppedFiles.begin(), report.droppedFiles.end());

    result.behaviors = allBehaviors;

    SandboxVerdict verdict = computeVerdict(allBehaviors);
    switch (verdict) {
        case SandboxVerdict::Clean:
            result.verdict = "clean";
            result.score = 0.0;
            break;
        case SandboxVerdict::Suspicious:
            result.verdict = "suspicious";
            result.score = 50.0;
            break;
        case SandboxVerdict::Malicious:
            result.verdict = "malicious";
            result.score = 90.0;
            break;
        default:
            result.verdict = "unknown";
            result.score = 0.0;
            break;
    }

    result.sampleHash = "sha256:" + sampleId;
    return result;
}

std::vector<IOCInfo> SandboxEngine::getIOCs(const std::string& sampleId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto reportIt = reports_.find(sampleId);
    if (reportIt == reports_.end()) {
        logger_.warn("No report found for IOC extraction: {}", sampleId);
        return {};
    }

    return extractIOCs(reportIt->second);
}

BehaviorReport SandboxEngine::getBehaviorReport(const std::string& sampleId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = reports_.find(sampleId);
    if (it == reports_.end()) {
        logger_.warn("No behavior report found for: {}", sampleId);
        return {sampleId, {}, {}, {}, {}, {}};
    }
    return it->second;
}

std::string SandboxEngine::detonateURL(const std::string& url) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (url.empty()) {
        logger_.error("Cannot detonate: empty URL");
        return "";
    }

    std::string sampleId = generateSampleId();
    std::string jobId = generateJobId();

    DetonationConfig config;
    config.samplePath = url;
    config.profileId = "PROF-DEFAULT-DEEP";
    config.priority = DetonationPriority::Normal;

    DetonationJob job;
    job.id = jobId;
    job.config = config;
    job.status = DetonationStatus::Running;
    job.submittedAt = getCurrentTimestamp();
    job.startedAt = getCurrentTimestamp();

    jobs_[jobId] = job;
    sampleToJob_[sampleId] = jobId;

    // Initialize behavior report for URL analysis
    BehaviorReport report;
    report.sampleId = sampleId;
    report.networkConnections.push_back(url);
    reports_[sampleId] = report;

    logger_.info("URL detonation started: {} -> {} (job {})", url, sampleId, jobId);
    return sampleId;
}

std::string SandboxEngine::createProfile(const SandboxProfile& profile) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string profileId = generateProfileId();

    SandboxProfile newProfile = profile;
    newProfile.id = profileId;

    profiles_[profileId] = newProfile;
    logger_.info("Created profile: {} ({})", newProfile.name, profileId);
    return profileId;
}

std::vector<SandboxProfile> SandboxEngine::getProfiles() {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<SandboxProfile> result;
    result.reserve(profiles_.size());
    for (const auto& [id, profile] : profiles_) {
        result.push_back(profile);
    }
    return result;
}

std::optional<SandboxProfile> SandboxEngine::getProfile(const std::string& profileId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = profiles_.find(profileId);
    if (it == profiles_.end()) {
        return std::nullopt;
    }
    return it->second;
}

bool SandboxEngine::deleteProfile(const std::string& profileId) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Prevent deletion of default profiles
    if (profileId.find("PROF-DEFAULT-") == 0) {
        logger_.warn("Cannot delete default profile: {}", profileId);
        return false;
    }

    auto it = profiles_.find(profileId);
    if (it == profiles_.end()) {
        logger_.error("Cannot delete: profile {} not found", profileId);
        return false;
    }

    profiles_.erase(it);
    logger_.info("Deleted profile: {}", profileId);
    return true;
}

std::vector<NetworkActivity> SandboxEngine::getNetworkActivity(const std::string& sampleId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = networkActivities_.find(sampleId);
    if (it == networkActivities_.end()) {
        return {};
    }
    return it->second;
}

SandboxVerdict SandboxEngine::getVerdict(const std::string& sampleId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto reportIt = reports_.find(sampleId);
    if (reportIt == reports_.end()) {
        return SandboxVerdict::Unknown;
    }

    // Aggregate all behaviors
    const auto& report = reportIt->second;
    std::vector<std::string> allBehaviors;
    allBehaviors.insert(allBehaviors.end(), report.processesCreated.begin(), report.processesCreated.end());
    allBehaviors.insert(allBehaviors.end(), report.filesModified.begin(), report.filesModified.end());
    allBehaviors.insert(allBehaviors.end(), report.registryChanges.begin(), report.registryChanges.end());
    allBehaviors.insert(allBehaviors.end(), report.networkConnections.begin(), report.networkConnections.end());
    allBehaviors.insert(allBehaviors.end(), report.droppedFiles.begin(), report.droppedFiles.end());

    return computeVerdict(allBehaviors);
}

void SandboxEngine::addBehavior(const std::string& sampleId, const std::string& behavior) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = reports_.find(sampleId);
    if (it == reports_.end()) {
        BehaviorReport report;
        report.sampleId = sampleId;
        report.processesCreated.push_back(behavior);
        reports_[sampleId] = report;
    } else {
        it->second.processesCreated.push_back(behavior);
    }
}

void SandboxEngine::addNetworkActivity(const std::string& sampleId, const NetworkActivity& activity) {
    std::lock_guard<std::mutex> lock(mutex_);
    networkActivities_[sampleId].push_back(activity);

    // Also record in behavior report
    auto it = reports_.find(sampleId);
    if (it != reports_.end()) {
        it->second.networkConnections.push_back(activity.destination + ":" + std::to_string(activity.port));
    }
}

void SandboxEngine::completeDetonation(const std::string& jobId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = jobs_.find(jobId);
    if (it == jobs_.end()) {
        logger_.error("Cannot complete: job {} not found", jobId);
        return;
    }

    it->second.status = DetonationStatus::Completed;
    it->second.completedAt = getCurrentTimestamp();
    logger_.info("Completed detonation job: {}", jobId);
}

} // namespace ThreatOne::Sandbox
