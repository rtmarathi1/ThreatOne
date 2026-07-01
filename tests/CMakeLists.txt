# Tests CMakeLists.txt - Unit test runner using doctest

find_package(Threads REQUIRED)

# Collect all test source files
set(TEST_SOURCES
    test_main.cpp
    core/test_logger.cpp
    core/test_config.cpp
    core/test_event_bus.cpp
    core/test_service_locator.cpp
    database/test_query_builder.cpp
    database/test_migration.cpp
    scanner/test_file_hasher.cpp
    scanner/test_signature_database.cpp
    scanner/test_signature_matcher.cpp
    scanner/test_file_enumerator.cpp
    scanner/test_quarantine_manager.cpp
    scanner/test_scan_engine.cpp
)

# Create the test executable
add_executable(threatone_tests ${TEST_SOURCES})

target_include_directories(threatone_tests
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src/core/include
        ${CMAKE_SOURCE_DIR}/src/database/include
        ${CMAKE_SOURCE_DIR}/src/utils/include
        ${CMAKE_SOURCE_DIR}/src/scanner/include
)

target_link_libraries(threatone_tests
    PRIVATE
        doctest
        threatone_core
        threatone_database
        threatone_utils
        threatone_scanner
        spdlog
        nlohmann_json
        sqlite3
        Threads::Threads
)

# Register with CTest
add_test(NAME threatone_tests COMMAND threatone_tests)
