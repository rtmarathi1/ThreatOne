add_library(threatone_compliance STATIC
    src/ComplianceEngine.cpp
    src/ComplianceFramework.cpp
    src/ComplianceScanner.cpp
    src/ComplianceScoring.cpp
    src/EvidenceCollector.cpp
    src/RemediationTracker.cpp
)

target_include_directories(threatone_compliance
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_compliance
    PUBLIC
        threatone_compiler_options
        threatone_core
    PRIVATE
        nlohmann_json
)
