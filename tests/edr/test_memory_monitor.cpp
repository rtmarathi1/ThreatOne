#include <doctest/doctest.h>
#include <edr/MemoryMonitor.h>

#include <unistd.h>

using namespace ThreatOne::EDR;

TEST_CASE("MemoryMonitor - get memory regions") {
    MemoryMonitor monitor;

    SUBCASE("Can read memory regions for current process") {
        uint64_t myPid = static_cast<uint64_t>(getpid());
        auto regions = monitor.getMemoryRegions(myPid);

        // Current process must have some memory regions
        CHECK(!regions.empty());

        // Check that regions have valid addresses
        for (const auto& region : regions) {
            CHECK(region.endAddr > region.startAddr);
            CHECK(!region.permissions.empty());
        }
    }

    SUBCASE("Memory regions include expected sections") {
        uint64_t myPid = static_cast<uint64_t>(getpid());
        auto regions = monitor.getMemoryRegions(myPid);

        // Should have at least stack and heap regions
        bool hasStack = false;
        bool hasHeap = false;
        for (const auto& region : regions) {
            if (region.pathname.find("[stack]") != std::string::npos) hasStack = true;
            if (region.pathname.find("[heap]") != std::string::npos) hasHeap = true;
        }
        CHECK(hasStack);
        // Heap may not always be present in test env, don't require it
    }

    SUBCASE("Invalid PID returns empty") {
        auto regions = monitor.getMemoryRegions(999999999);
        CHECK(regions.empty());
    }
}

TEST_CASE("MemoryMonitor - entropy calculation") {
    MemoryMonitor monitor;

    SUBCASE("Empty data returns zero entropy") {
        std::vector<uint8_t> empty;
        auto result = monitor.calculateMemoryEntropy(empty);
        CHECK(result.entropy == 0.0);
        CHECK(!result.isPacked);
        CHECK(result.regionSize == 0);
    }

    SUBCASE("Uniform data has zero entropy") {
        std::vector<uint8_t> uniform(256, 0x41); // All 'A'
        auto result = monitor.calculateMemoryEntropy(uniform);
        CHECK(result.entropy == doctest::Approx(0.0));
        CHECK(!result.isPacked);
    }

    SUBCASE("Random-like data has high entropy") {
        // Create data with all 256 byte values equally distributed
        std::vector<uint8_t> random;
        for (int i = 0; i < 256; i++) {
            for (int j = 0; j < 4; j++) {
                random.push_back(static_cast<uint8_t>(i));
            }
        }
        auto result = monitor.calculateMemoryEntropy(random);
        CHECK(result.entropy > 7.9);
        CHECK(result.isPacked);
    }

    SUBCASE("Two distinct values have entropy of 1.0") {
        std::vector<uint8_t> binary;
        for (int i = 0; i < 128; i++) binary.push_back(0x00);
        for (int i = 0; i < 128; i++) binary.push_back(0xFF);
        auto result = monitor.calculateMemoryEntropy(binary);
        CHECK(result.entropy == doctest::Approx(1.0).epsilon(0.01));
    }

    SUBCASE("Region size is reported correctly") {
        std::vector<uint8_t> data(100, 0x42);
        auto result = monitor.calculateMemoryEntropy(data);
        CHECK(result.regionSize == 100);
    }
}

TEST_CASE("MemoryMonitor - shellcode detection") {
    MemoryMonitor monitor;

    SUBCASE("NOP sled detection") {
        // Create a buffer with a NOP sled (16+ 0x90 bytes)
        std::vector<uint8_t> data(100, 0x00);
        for (int i = 20; i < 40; i++) {
            data[i] = 0x90; // NOP instruction
        }
        CHECK(monitor.detectShellcodePatterns(data));
    }

    SUBCASE("Clean data does not trigger") {
        // Regular data without shellcode patterns
        std::vector<uint8_t> cleanData;
        for (int i = 0; i < 256; i++) {
            cleanData.push_back(static_cast<uint8_t>(i % 128 + 32)); // Printable ASCII-ish
        }
        CHECK(!monitor.detectShellcodePatterns(cleanData));
    }

    SUBCASE("Known shellcode pattern triggers detection") {
        // Linux x86 int 0x80 pattern: 31 c0 50 68
        std::vector<uint8_t> shellcode = {
            0x00, 0x00, 0x31, 0xc0, 0x50, 0x68, 0x00, 0x00
        };
        CHECK(monitor.detectShellcodePatterns(shellcode));
    }

    SUBCASE("Too short data does not crash") {
        std::vector<uint8_t> tiny = {0x01};
        CHECK(!monitor.detectShellcodePatterns(tiny));

        std::vector<uint8_t> empty;
        CHECK(!monitor.detectShellcodePatterns(empty));
    }
}

TEST_CASE("MemoryMonitor - code injection detection") {
    MemoryMonitor monitor;

    SUBCASE("Scan current process for injection indicators") {
        uint64_t myPid = static_cast<uint64_t>(getpid());
        auto indicators = monitor.scanProcessMemory(myPid);

        // Current process should not typically have code injection
        // but may have RWX regions in some environments (JIT, etc.)
        // Just verify it doesn't crash and returns valid data
        for (const auto& ind : indicators) {
            CHECK(!ind.type.empty());
            CHECK(ind.severity >= 0.0);
            CHECK(ind.severity <= 1.0);
        }
    }

    SUBCASE("detectCodeInjection is equivalent to scanProcessMemory") {
        uint64_t myPid = static_cast<uint64_t>(getpid());
        auto scan = monitor.scanProcessMemory(myPid);
        auto detect = monitor.detectCodeInjection(myPid);
        CHECK(scan.size() == detect.size());
    }
}
