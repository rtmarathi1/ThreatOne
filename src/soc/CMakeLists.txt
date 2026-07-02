find_package(Threads REQUIRED)

add_library(threatone_soc STATIC
    src/SOCManager.cpp
    src/CaseManager.cpp
    src/IncidentManager.cpp
    src/PlaybookEngine.cpp
    src/WorkflowAutomation.cpp
    src/EvidenceCollector.cpp
    src/TimelineBuilder.cpp
    src/SOCDashboardData.cpp
    src/AlertTriage.cpp
)

target_include_directories(threatone_soc
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_soc
    PUBLIC
        threatone_compiler_options
        threatone_core
        Threads::Threads
)
