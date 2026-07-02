find_package(Threads REQUIRED)

add_library(threatone_sandbox STATIC
    src/SandboxEngine.cpp
    src/ProcessSandbox.cpp
    src/NetworkSandbox.cpp
    src/BehaviorRecorder.cpp
    src/SandboxAnalyzer.cpp
    src/MalwareDetonation.cpp
    src/SandboxReporter.cpp
)

target_include_directories(threatone_sandbox
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_sandbox
    PUBLIC
        threatone_compiler_options
        threatone_core
        Threads::Threads
)
