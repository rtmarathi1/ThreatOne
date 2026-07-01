#include <doctest/doctest.h>
#include <sandbox/SandboxEngine.h>

using namespace ThreatOne::Sandbox;

TEST_CASE("SandboxEngine - Submit sample basic") {
    SandboxEngine engine;

    auto sampleId = engine.submitSample("/tmp/malware.exe");
    CHECK_FALSE(sampleId.empty());
    CHECK(sampleId.find("SAMPLE-") == 0);
}

TEST_CASE("SandboxEngine - Submit sample empty path fails") {
    SandboxEngine engine;

    auto sampleId = engine.submitSample("");
    CHECK(sampleId.empty());
}

TEST_CASE("SandboxEngine - Submit sample with profile") {
    SandboxEngine engine;

    DetonationConfig config;
    config.samplePath = "/tmp/suspicious.exe";
    config.profileId = "PROF-DEFAULT-DEEP";
    config.priority = DetonationPriority::High;

    auto jobId = engine.submitWithProfile(config);
    CHECK_FALSE(jobId.empty());
    CHECK(jobId.find("JOB-") == 0);
}

TEST_CASE("SandboxEngine - Submit with invalid profile fails") {
    SandboxEngine engine;

    DetonationConfig config;
    config.samplePath = "/tmp/test.exe";
    config.profileId = "NONEXISTENT";

    auto jobId = engine.submitWithProfile(config);
    CHECK(jobId.empty());
}

TEST_CASE("SandboxEngine - Detonation job lifecycle") {
    SandboxEngine engine;

    DetonationConfig config;
    config.samplePath = "/tmp/sample.exe";
    config.profileId = "PROF-DEFAULT-QUICK";
    config.priority = DetonationPriority::Normal;

    auto jobId = engine.submitWithProfile(config);
    REQUIRE_FALSE(jobId.empty());

    // Initially queued
    auto status = engine.getDetonationStatus(jobId);
    REQUIRE(status.has_value());
    CHECK(status.value() == DetonationStatus::Queued);

    // Complete the job
    engine.completeDetonation(jobId);
    status = engine.getDetonationStatus(jobId);
    REQUIRE(status.has_value());
    CHECK(status.value() == DetonationStatus::Completed);
}

TEST_CASE("SandboxEngine - Cancel detonation") {
    SandboxEngine engine;

    DetonationConfig config;
    config.samplePath = "/tmp/sample.exe";
    config.profileId = "PROF-DEFAULT-QUICK";

    auto jobId = engine.submitWithProfile(config);
    REQUIRE_FALSE(jobId.empty());

    CHECK(engine.cancelDetonation(jobId));

    auto status = engine.getDetonationStatus(jobId);
    REQUIRE(status.has_value());
    CHECK(status.value() == DetonationStatus::Failed);
}

TEST_CASE("SandboxEngine - Cancel completed job fails") {
    SandboxEngine engine;

    DetonationConfig config;
    config.samplePath = "/tmp/sample.exe";
    config.profileId = "PROF-DEFAULT-QUICK";

    auto jobId = engine.submitWithProfile(config);
    engine.completeDetonation(jobId);

    CHECK_FALSE(engine.cancelDetonation(jobId));
}

TEST_CASE("SandboxEngine - Cancel nonexistent job fails") {
    SandboxEngine engine;
    CHECK_FALSE(engine.cancelDetonation("NONEXISTENT"));
}

TEST_CASE("SandboxEngine - Get detonation status nonexistent") {
    SandboxEngine engine;
    auto status = engine.getDetonationStatus("NONEXISTENT");
    CHECK_FALSE(status.has_value());
}

TEST_CASE("SandboxEngine - Verdict clean with no behaviors") {
    SandboxEngine engine;

    auto sampleId = engine.submitSample("/tmp/benign.exe");
    REQUIRE_FALSE(sampleId.empty());

    auto verdict = engine.getVerdict(sampleId);
    CHECK(verdict == SandboxVerdict::Clean);

    auto analysis = engine.getAnalysis(sampleId);
    CHECK(analysis.verdict == "clean");
    CHECK(analysis.score == 0.0);
}

TEST_CASE("SandboxEngine - Verdict suspicious with 1-2 behaviors") {
    SandboxEngine engine;

    auto sampleId = engine.submitSample("/tmp/suspect.exe");
    REQUIRE_FALSE(sampleId.empty());

    engine.addBehavior(sampleId, "created process cmd.exe");

    auto verdict = engine.getVerdict(sampleId);
    CHECK(verdict == SandboxVerdict::Suspicious);

    auto analysis = engine.getAnalysis(sampleId);
    CHECK(analysis.verdict == "suspicious");
    CHECK(analysis.score == 50.0);
}

TEST_CASE("SandboxEngine - Verdict malicious with 3+ behaviors") {
    SandboxEngine engine;

    auto sampleId = engine.submitSample("/tmp/malware.exe");
    REQUIRE_FALSE(sampleId.empty());

    engine.addBehavior(sampleId, "created process cmd.exe");
    engine.addBehavior(sampleId, "created process powershell.exe");
    engine.addBehavior(sampleId, "created process reg.exe");

    auto verdict = engine.getVerdict(sampleId);
    CHECK(verdict == SandboxVerdict::Malicious);

    auto analysis = engine.getAnalysis(sampleId);
    CHECK(analysis.verdict == "malicious");
    CHECK(analysis.score == 90.0);
}

TEST_CASE("SandboxEngine - Verdict unknown for nonexistent sample") {
    SandboxEngine engine;
    auto verdict = engine.getVerdict("NONEXISTENT");
    CHECK(verdict == SandboxVerdict::Unknown);
}

TEST_CASE("SandboxEngine - IOC extraction from behaviors") {
    SandboxEngine engine;

    auto sampleId = engine.submitSample("/tmp/malware.exe");
    REQUIRE_FALSE(sampleId.empty());

    // Add network activity to trigger IOCs
    NetworkActivity netActivity;
    netActivity.protocol = "TCP";
    netActivity.destination = "192.168.1.100";
    netActivity.port = 4444;
    netActivity.data = "C2 beacon";
    netActivity.timestamp = "2024-01-01T00:00:00Z";
    engine.addNetworkActivity(sampleId, netActivity);

    auto iocs = engine.getIOCs(sampleId);
    CHECK_FALSE(iocs.empty());

    // Should contain IP IOC from network connection
    bool foundIp = false;
    for (const auto& ioc : iocs) {
        if (ioc.type == "ip") {
            foundIp = true;
            break;
        }
    }
    CHECK(foundIp);
}

TEST_CASE("SandboxEngine - Behavior report aggregation") {
    SandboxEngine engine;

    auto sampleId = engine.submitSample("/tmp/test.exe");
    REQUIRE_FALSE(sampleId.empty());

    engine.addBehavior(sampleId, "created explorer.exe");
    engine.addBehavior(sampleId, "created cmd.exe");

    auto report = engine.getBehaviorReport(sampleId);
    CHECK(report.sampleId == sampleId);
    CHECK(report.processesCreated.size() == 2);
}

TEST_CASE("SandboxEngine - Behavior report nonexistent sample") {
    SandboxEngine engine;

    auto report = engine.getBehaviorReport("NONEXISTENT");
    CHECK(report.sampleId == "NONEXISTENT");
    CHECK(report.processesCreated.empty());
}

TEST_CASE("SandboxEngine - URL detonation") {
    SandboxEngine engine;

    auto sampleId = engine.detonateURL("http://malicious-site.com/payload");
    CHECK_FALSE(sampleId.empty());

    // URL detonation should have at least one network connection recorded
    auto report = engine.getBehaviorReport(sampleId);
    CHECK_FALSE(report.networkConnections.empty());

    // Verdict should be suspicious (1 behavior: the URL connection)
    auto verdict = engine.getVerdict(sampleId);
    CHECK(verdict == SandboxVerdict::Suspicious);
}

TEST_CASE("SandboxEngine - URL detonation empty URL fails") {
    SandboxEngine engine;
    auto sampleId = engine.detonateURL("");
    CHECK(sampleId.empty());
}

TEST_CASE("SandboxEngine - Profile CRUD") {
    SandboxEngine engine;

    // Default profiles should exist
    auto profiles = engine.getProfiles();
    REQUIRE(profiles.size() >= 3);

    // Create a new profile
    SandboxProfile newProfile;
    newProfile.name = "Test Profile";
    newProfile.type = ProfileType::Custom;
    newProfile.timeoutSeconds = 180;
    newProfile.networkSimulation = true;
    newProfile.recordRegistry = false;
    newProfile.recordFilesystem = true;
    newProfile.recordNetwork = true;

    auto profileId = engine.createProfile(newProfile);
    CHECK_FALSE(profileId.empty());
    CHECK(profileId.find("PROF-") == 0);

    // Get the profile
    auto retrieved = engine.getProfile(profileId);
    REQUIRE(retrieved.has_value());
    CHECK(retrieved->name == "Test Profile");
    CHECK(retrieved->type == ProfileType::Custom);
    CHECK(retrieved->timeoutSeconds == 180);
    CHECK(retrieved->networkSimulation == true);
    CHECK(retrieved->recordRegistry == false);

    // Delete the profile
    CHECK(engine.deleteProfile(profileId));

    // Verify it is gone
    auto deleted = engine.getProfile(profileId);
    CHECK_FALSE(deleted.has_value());
}

TEST_CASE("SandboxEngine - Cannot delete default profiles") {
    SandboxEngine engine;

    CHECK_FALSE(engine.deleteProfile("PROF-DEFAULT-QUICK"));
    CHECK_FALSE(engine.deleteProfile("PROF-DEFAULT-DEEP"));
    CHECK_FALSE(engine.deleteProfile("PROF-DEFAULT-CUSTOM"));
}

TEST_CASE("SandboxEngine - Get nonexistent profile") {
    SandboxEngine engine;
    auto profile = engine.getProfile("NONEXISTENT");
    CHECK_FALSE(profile.has_value());
}

TEST_CASE("SandboxEngine - Delete nonexistent profile fails") {
    SandboxEngine engine;
    CHECK_FALSE(engine.deleteProfile("NONEXISTENT"));
}

TEST_CASE("SandboxEngine - Network activity recording") {
    SandboxEngine engine;

    auto sampleId = engine.submitSample("/tmp/test.exe");
    REQUIRE_FALSE(sampleId.empty());

    NetworkActivity activity1;
    activity1.protocol = "TCP";
    activity1.destination = "10.0.0.1";
    activity1.port = 80;
    activity1.data = "GET / HTTP/1.1";
    activity1.timestamp = "2024-01-01T00:00:00Z";

    NetworkActivity activity2;
    activity2.protocol = "UDP";
    activity2.destination = "8.8.8.8";
    activity2.port = 53;
    activity2.data = "DNS query";
    activity2.timestamp = "2024-01-01T00:00:01Z";

    engine.addNetworkActivity(sampleId, activity1);
    engine.addNetworkActivity(sampleId, activity2);

    auto activities = engine.getNetworkActivity(sampleId);
    REQUIRE(activities.size() == 2);
    CHECK(activities[0].destination == "10.0.0.1");
    CHECK(activities[0].port == 80);
    CHECK(activities[1].destination == "8.8.8.8");
    CHECK(activities[1].port == 53);
}

TEST_CASE("SandboxEngine - Network activity empty for unknown sample") {
    SandboxEngine engine;
    auto activities = engine.getNetworkActivity("NONEXISTENT");
    CHECK(activities.empty());
}

TEST_CASE("SandboxEngine - Default profiles are pre-loaded") {
    SandboxEngine engine;

    auto quick = engine.getProfile("PROF-DEFAULT-QUICK");
    REQUIRE(quick.has_value());
    CHECK(quick->name == "Quick Analysis");
    CHECK(quick->type == ProfileType::Quick);
    CHECK(quick->timeoutSeconds == 30);

    auto deep = engine.getProfile("PROF-DEFAULT-DEEP");
    REQUIRE(deep.has_value());
    CHECK(deep->name == "Deep Analysis");
    CHECK(deep->type == ProfileType::Deep);
    CHECK(deep->timeoutSeconds == 300);
    CHECK(deep->networkSimulation == true);

    auto custom = engine.getProfile("PROF-DEFAULT-CUSTOM");
    REQUIRE(custom.has_value());
    CHECK(custom->name == "Custom Analysis");
    CHECK(custom->type == ProfileType::Custom);
}
