find_package(Threads REQUIRED)

add_library(threatone_monitor STATIC
    src/MonitorEngine.cpp
)

target_include_directories(threatone_monitor
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_monitor
    PUBLIC
        threatone_compiler_options
        threatone_core
        threatone_edr
        nlohmann_json
        Threads::Threads
)
