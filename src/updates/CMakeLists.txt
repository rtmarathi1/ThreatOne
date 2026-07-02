find_package(Threads REQUIRED)

add_library(threatone_updates STATIC
    src/UpdateManager.cpp
    src/VersionChecker.cpp
    src/DeltaUpdater.cpp
    src/RollbackManager.cpp
    src/UpdateVerifier.cpp
    src/ChannelManager.cpp
    src/UpdateScheduler.cpp
)

target_include_directories(threatone_updates
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_updates
    PUBLIC
        threatone_compiler_options
        threatone_core
        Threads::Threads
)
