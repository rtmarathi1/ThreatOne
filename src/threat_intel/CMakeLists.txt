find_package(Threads REQUIRED)

add_library(threatone_threat_intel STATIC
    src/IOCManager.cpp
    src/StixParser.cpp
    src/CsvParser.cpp
    src/PlainTextParser.cpp
    src/OpenIOCParser.cpp
    src/ThreatFeedManager.cpp
)

target_include_directories(threatone_threat_intel
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_threat_intel
    PUBLIC
        threatone_compiler_options
        threatone_core
        nlohmann_json
        Threads::Threads
)
