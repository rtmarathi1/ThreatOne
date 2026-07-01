find_package(Threads REQUIRED)

add_library(threatone_scanner STATIC
    src/ScanEngine.cpp
    src/FileHasher.cpp
    src/SignatureDatabase.cpp
    src/SignatureMatcher.cpp
    src/YaraEngine.cpp
    src/ScanScheduler.cpp
    src/FileEnumerator.cpp
    src/ScanProgress.cpp
    src/QuarantineManager.cpp
    src/ScanHistory.cpp
)

target_include_directories(threatone_scanner
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_scanner
    PUBLIC
        threatone_compiler_options
        threatone_core
        threatone_database
        nlohmann_json
        sqlite3
        Threads::Threads
)

# Conditionally link OpenSSL for FileHasher
if(ENABLE_OPENSSL AND OpenSSL_FOUND)
    target_link_libraries(threatone_scanner PUBLIC OpenSSL::Crypto)
    target_compile_definitions(threatone_scanner PUBLIC HAS_OPENSSL)
endif()

# Conditionally link YARA for YaraEngine
if(ENABLE_YARA AND YARA_FOUND)
    target_include_directories(threatone_scanner PUBLIC ${YARA_INCLUDE_DIRS})
    target_link_libraries(threatone_scanner PUBLIC ${YARA_LIBRARIES})
    target_compile_definitions(threatone_scanner PUBLIC HAS_YARA)
endif()
