add_library(threatone_telemetry STATIC
    src/TelemetryManager.cpp
)

target_include_directories(threatone_telemetry
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_telemetry
    PUBLIC
        threatone_compiler_options
        threatone_core
)
