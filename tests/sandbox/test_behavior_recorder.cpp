#include <doctest/doctest.h>
#include <sandbox/SandboxEngine.h>

using namespace ThreatOne::Sandbox;

TEST_CASE("BehaviorRecorder - Start recording session") {
    SandboxEngine engine;
    auto& br = engine.getBehaviorRecorder();

    auto sessionId = br.startRecording("SAMPLE-1");
    CHECK_FALSE(sessionId.empty());
    CHECK(sessionId.find("REC-") == 0);

    auto session = br.getSession(sessionId);
    REQUIRE(session.has_value());
    CHECK(session->sampleId == "SAMPLE-1");
    CHECK(session->active == true);
}

TEST_CASE("BehaviorRecorder - Stop recording") {
    SandboxEngine engine;
    auto& br = engine.getBehaviorRecorder();

    auto sessionId = br.startRecording("SAMPLE-1");
    CHECK(br.stopRecording(sessionId));

    auto session = br.getSession(sessionId);
    REQUIRE(session.has_value());
    CHECK(session->active == false);
}

TEST_CASE("BehaviorRecorder - Record various behaviors") {
    SandboxEngine engine;
    auto& br = engine.getBehaviorRecorder();

    br.startRecording("SAMPLE-1");

    auto id1 = br.recordFileOperation("SAMPLE-1", "write", "/tmp/payload.exe");
    auto id2 = br.recordRegistryChange("SAMPLE-1", "modify", "HKLM\\Run\\malware");
    auto id3 = br.recordProcessCreation("SAMPLE-1", "cmd.exe", "cmd /c whoami");
    auto id4 = br.recordNetworkConnection("SAMPLE-1", "10.0.0.1", 4444);
    auto id5 = br.recordFileDrop("SAMPLE-1", "/tmp/dropped.dll", "abc123");

    CHECK_FALSE(id1.empty());
    CHECK_FALSE(id2.empty());
    CHECK_FALSE(id3.empty());
    CHECK_FALSE(id4.empty());
    CHECK_FALSE(id5.empty());

    CHECK(br.getBehaviorCount("SAMPLE-1") == 5);
}

TEST_CASE("BehaviorRecorder - Get behaviors by type") {
    SandboxEngine engine;
    auto& br = engine.getBehaviorRecorder();

    br.recordProcessCreation("SAMPLE-1", "cmd.exe", "");
    br.recordProcessCreation("SAMPLE-1", "powershell.exe", "");
    br.recordFileOperation("SAMPLE-1", "write", "/tmp/x");

    auto processes = br.getBehaviorsByType("SAMPLE-1", BehaviorType::ProcessCreation);
    CHECK(processes.size() == 2);

    auto files = br.getBehaviorsByType("SAMPLE-1", BehaviorType::FileOperation);
    CHECK(files.size() == 1);
}

TEST_CASE("BehaviorRecorder - Generate behavior report") {
    SandboxEngine engine;
    auto& br = engine.getBehaviorRecorder();

    br.recordProcessCreation("SAMPLE-1", "malware.exe", "");
    br.recordFileOperation("SAMPLE-1", "write", "/tmp/payload");
    br.recordRegistryChange("SAMPLE-1", "set", "HKLM\\Run\\x");
    br.recordNetworkConnection("SAMPLE-1", "evil.com", 443);
    br.recordFileDrop("SAMPLE-1", "/tmp/dropped.exe", "hash123");

    auto report = br.generateBehaviorReport("SAMPLE-1");
    CHECK(report.sampleId == "SAMPLE-1");
    CHECK(report.processesCreated.size() == 1);
    CHECK(report.filesModified.size() == 1);
    CHECK(report.registryChanges.size() == 1);
    CHECK(report.networkConnections.size() == 1);
    CHECK(report.droppedFiles.size() == 1);
}

TEST_CASE("BehaviorRecorder - Active sessions") {
    SandboxEngine engine;
    auto& br = engine.getBehaviorRecorder();

    auto s1 = br.startRecording("S1");
    auto s2 = br.startRecording("S2");

    CHECK(br.getActiveSessionCount() == 2);
    br.stopRecording(s1);
    CHECK(br.getActiveSessionCount() == 1);
}
