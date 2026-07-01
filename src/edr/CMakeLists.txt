find_package(Threads REQUIRED)

add_library(threatone_edr STATIC
    src/EDREngine.cpp
    src/ProcessMonitor.cpp
    src/FileMonitor.cpp
    src/RegistryMonitor.cpp
    src/MemoryMonitor.cpp
    src/TelemetryCollector.cpp
    src/BehaviorAnalyzer.cpp
    src/DetectionRulesEngine.cpp
    src/AlertManager.cpp
    src/PersistenceDetection.cpp
    src/RansomwareDetection.cpp
    src/LateralMovementDetection.cpp
    src/IncidentTimeline.cpp
)

target_include_directories(threatone_edr
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_edr
    PUBLIC
        threatone_compiler_options
        threatone_core
        nlohmann_json
        Threads::Threads
)
