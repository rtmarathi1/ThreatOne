#include <doctest/doctest.h>
#include <sandbox/SandboxEngine.h>

using namespace ThreatOne::Sandbox;

TEST_CASE("ProcessSandbox - Create process") {
    SandboxEngine engine;
    auto& ps = engine.getProcessSandbox();

    auto id = ps.createProcess("/tmp/malware.exe", {"--arg1"});
    CHECK_FALSE(id.empty());
    CHECK(id.find("PROC-") == 0);

    auto proc = ps.getProcess(id);
    REQUIRE(proc.has_value());
    CHECK(proc->executablePath == "/tmp/malware.exe");
    CHECK(proc->state == ProcessState::Created);
}

TEST_CASE("ProcessSandbox - Create process empty path fails") {
    SandboxEngine engine;
    auto& ps = engine.getProcessSandbox();

    auto id = ps.createProcess("", {});
    CHECK(id.empty());
}

TEST_CASE("ProcessSandbox - Process lifecycle") {
    SandboxEngine engine;
    auto& ps = engine.getProcessSandbox();

    auto id = ps.createProcess("/bin/test", {});
    CHECK(ps.startProcess(id));

    auto proc = ps.getProcess(id);
    CHECK(proc->state == ProcessState::Running);

    CHECK(ps.suspendProcess(id));
    proc = ps.getProcess(id);
    CHECK(proc->state == ProcessState::Suspended);

    CHECK(ps.resumeProcess(id));
    proc = ps.getProcess(id);
    CHECK(proc->state == ProcessState::Running);

    CHECK(ps.terminateProcess(id, 0));
    proc = ps.getProcess(id);
    CHECK(proc->state == ProcessState::Terminated);
    CHECK(proc->exitCode == 0);
}

TEST_CASE("ProcessSandbox - Cannot start already running") {
    SandboxEngine engine;
    auto& ps = engine.getProcessSandbox();

    auto id = ps.createProcess("/bin/test", {});
    ps.startProcess(id);
    CHECK_FALSE(ps.startProcess(id));
}

TEST_CASE("ProcessSandbox - Filesystem restrictions") {
    SandboxEngine engine;
    auto& ps = engine.getProcessSandbox();

    auto id = ps.createProcess("/bin/test", {});

    FilesystemRestriction restriction;
    restriction.path = "/tmp/";
    restriction.readable = true;
    restriction.writable = false;
    CHECK(ps.addFilesystemRestriction(id, restriction));

    CHECK(ps.isPathAllowed(id, "/tmp/file.txt", false));
    CHECK_FALSE(ps.isPathAllowed(id, "/tmp/file.txt", true));
    CHECK_FALSE(ps.isPathAllowed(id, "/etc/passwd", false));
}

TEST_CASE("ProcessSandbox - Network restrictions") {
    SandboxEngine engine;
    auto& ps = engine.getProcessSandbox();

    auto id = ps.createProcess("/bin/test", {});

    NetworkRestriction restriction;
    restriction.allowOutbound = true;
    restriction.allowedHosts = {"api.example.com"};
    restriction.allowedPorts = {443};
    CHECK(ps.setNetworkRestriction(id, restriction));

    CHECK(ps.isNetworkAllowed(id, "api.example.com", 443));
    CHECK_FALSE(ps.isNetworkAllowed(id, "evil.com", 443));
    CHECK_FALSE(ps.isNetworkAllowed(id, "api.example.com", 80));
}

TEST_CASE("ProcessSandbox - Timeout") {
    SandboxEngine engine;
    auto& ps = engine.getProcessSandbox();

    auto id = ps.createProcess("/bin/test", {});
    ps.startProcess(id);
    CHECK(ps.timeoutProcess(id));

    auto proc = ps.getProcess(id);
    CHECK(proc->state == ProcessState::TimedOut);
}

TEST_CASE("ProcessSandbox - Active process count") {
    SandboxEngine engine;
    auto& ps = engine.getProcessSandbox();

    auto id1 = ps.createProcess("/bin/a", {});
    auto id2 = ps.createProcess("/bin/b", {});
    ps.startProcess(id1);
    ps.startProcess(id2);

    CHECK(ps.getActiveProcessCount() == 2);
    ps.terminateProcess(id1);
    CHECK(ps.getActiveProcessCount() == 1);
}
