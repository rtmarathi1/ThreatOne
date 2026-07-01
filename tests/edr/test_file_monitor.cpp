#include <doctest/doctest.h>
#include <edr/FileMonitor.h>

#include <fstream>
#include <filesystem>
#include <thread>
#include <chrono>

using namespace ThreatOne::EDR;
namespace fs = std::filesystem;

TEST_CASE("FileMonitor - watch directory and detect creation") {
    auto tempDir = fs::temp_directory_path() / "threatone_test_filemon";
    fs::create_directories(tempDir);

    FileMonitor monitor;
    monitor.watchDirectory(tempDir);

    SUBCASE("Detect new file creation") {
        // Create a file after watching starts
        auto testFile = tempDir / "new_file.txt";
        {
            std::ofstream f(testFile);
            f << "test content";
        }

        // Poll to detect changes
        monitor.poll();

        auto events = monitor.getEvents();
        REQUIRE(!events.empty());

        bool foundCreate = false;
        for (const auto& evt : events) {
            if (evt.action == "create" && evt.path == testFile.string()) {
                foundCreate = true;
            }
        }
        CHECK(foundCreate);

        fs::remove(testFile);
    }

    SUBCASE("Detect file modification") {
        // Create file first
        auto testFile = tempDir / "modify_test.txt";
        {
            std::ofstream f(testFile);
            f << "initial";
        }

        // Poll to register initial state
        monitor.poll();
        monitor.clearEvents();

        // Modify the file (need to change mtime)
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        {
            std::ofstream f(testFile);
            f << "modified content that is different";
        }

        // Poll again
        monitor.poll();

        auto events = monitor.getEvents();
        bool foundModify = false;
        for (const auto& evt : events) {
            if (evt.action == "modify" && evt.path == testFile.string()) {
                foundModify = true;
            }
        }
        CHECK(foundModify);

        fs::remove(testFile);
    }

    SUBCASE("Detect file deletion") {
        // Create file
        auto testFile = tempDir / "delete_test.txt";
        {
            std::ofstream f(testFile);
            f << "to be deleted";
        }

        // Poll to register state
        monitor.poll();
        monitor.clearEvents();

        // Delete the file
        fs::remove(testFile);

        // Poll again
        monitor.poll();

        auto events = monitor.getEvents();
        bool foundDelete = false;
        for (const auto& evt : events) {
            if (evt.action == "delete" && evt.path == testFile.string()) {
                foundDelete = true;
            }
        }
        CHECK(foundDelete);
    }

    fs::remove_all(tempDir);
}

TEST_CASE("FileMonitor - callback notification") {
    auto tempDir = fs::temp_directory_path() / "threatone_test_filemon_cb";
    fs::create_directories(tempDir);

    FileMonitor monitor;
    bool callbackFired = false;
    std::string callbackPath;

    monitor.setCallback([&](const FileEvent& evt) {
        callbackFired = true;
        callbackPath = evt.path;
    });

    monitor.watchDirectory(tempDir);

    // Create a file
    auto testFile = tempDir / "callback_test.txt";
    {
        std::ofstream f(testFile);
        f << "callback test";
    }

    monitor.poll();

    CHECK(callbackFired);
    CHECK(callbackPath == testFile.string());

    fs::remove_all(tempDir);
}

TEST_CASE("FileMonitor - suspicious operations detection") {
    auto tempDir = fs::temp_directory_path() / "threatone_test_suspicious";
    fs::create_directories(tempDir);

    // Create a subdirectory that looks like tmp
    auto tmpSubDir = tempDir / "tmp";
    fs::create_directories(tmpSubDir);

    FileMonitor monitor(2048);
    monitor.watchDirectory(tmpSubDir);

    SUBCASE("Detect mass file creation in temp") {
        // Create many files to trigger mass creation detection
        for (int i = 0; i < 15; i++) {
            std::ofstream f(tmpSubDir / ("file_" + std::to_string(i) + ".dat"));
            f << "data " << i;
        }

        monitor.poll();

        auto indicators = monitor.detectSuspiciousOperations();
        bool foundMassCreate = false;
        for (const auto& ind : indicators) {
            if (ind.type == "mass_create") foundMassCreate = true;
        }
        CHECK(foundMassCreate);
    }

    SUBCASE("Detect executable drop") {
        auto exeFile = tmpSubDir / "payload.sh";
        {
            std::ofstream f(exeFile);
            f << "#!/bin/bash\nmalicious commands";
        }

        monitor.poll();

        auto indicators = monitor.detectSuspiciousOperations();
        bool foundExeDrop = false;
        for (const auto& ind : indicators) {
            if (ind.type == "executable_drop") foundExeDrop = true;
        }
        CHECK(foundExeDrop);
    }

    SUBCASE("Detect hidden file creation") {
        auto hiddenFile = tmpSubDir / ".hidden_backdoor";
        {
            std::ofstream f(hiddenFile);
            f << "secret data";
        }

        monitor.poll();

        auto indicators = monitor.detectSuspiciousOperations();
        bool foundHidden = false;
        for (const auto& ind : indicators) {
            if (ind.type == "hidden_file") foundHidden = true;
        }
        CHECK(foundHidden);
    }

    fs::remove_all(tempDir);
}

TEST_CASE("FileMonitor - ring buffer overflow") {
    auto tempDir = fs::temp_directory_path() / "threatone_test_ringbuf";
    fs::create_directories(tempDir);

    // Small buffer to test overflow
    FileMonitor monitor(5);
    monitor.watchDirectory(tempDir);

    // Create more files than buffer capacity
    for (int i = 0; i < 10; i++) {
        std::ofstream f(tempDir / ("file_" + std::to_string(i) + ".txt"));
        f << "data";
    }

    monitor.poll();

    auto events = monitor.getEvents();
    // Ring buffer should contain at most 5 events
    CHECK(events.size() <= 5);

    fs::remove_all(tempDir);
}

TEST_CASE("FileMonitor - unwatch directory") {
    auto tempDir = fs::temp_directory_path() / "threatone_test_unwatch";
    fs::create_directories(tempDir);

    FileMonitor monitor;
    monitor.watchDirectory(tempDir);

    // Create a file and verify detection
    auto testFile = tempDir / "before_unwatch.txt";
    {
        std::ofstream f(testFile);
        f << "test";
    }
    monitor.poll();
    CHECK(!monitor.getEvents().empty());

    // Unwatch and clear
    monitor.unwatchDirectory(tempDir);
    monitor.clearEvents();

    // Create another file - should not be detected
    auto testFile2 = tempDir / "after_unwatch.txt";
    {
        std::ofstream f(testFile2);
        f << "test2";
    }
    monitor.poll();
    CHECK(monitor.getEvents().empty());

    fs::remove_all(tempDir);
}
