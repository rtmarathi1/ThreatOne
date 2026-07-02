find_package(Threads REQUIRED)

add_library(threatone_hids STATIC
    src/HIDSEngine.cpp
    src/FileIntegrityMonitor.cpp
    src/LogAnalyzer.cpp
    src/RootkitDetector.cpp
    src/PolicyChecker.cpp
    src/SystemCallMonitor.cpp
    src/ConfigAuditor.cpp
)

target_include_directories(threatone_hids
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_hids
    PUBLIC
        threatone_compiler_options
        threatone_core
        Threads::Threads
)
