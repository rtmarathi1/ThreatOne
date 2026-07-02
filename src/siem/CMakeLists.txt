find_package(Threads REQUIRED)

add_library(threatone_siem STATIC
    src/SIEMEngine.cpp
    src/LogCollector.cpp
    src/LogParser.cpp
    src/EventNormalizer.cpp
    src/LogStorage.cpp
    src/SearchEngine.cpp
    src/DetectionRules.cpp
    src/SigmaRuleEngine.cpp
    src/CorrelationEngine.cpp
    src/AlertEngine.cpp
)

target_include_directories(threatone_siem
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_siem
    PUBLIC
        threatone_compiler_options
        threatone_core
        Threads::Threads
)
