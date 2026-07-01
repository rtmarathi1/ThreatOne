cmake_minimum_required(VERSION 3.22)

project(ThreatOne
    VERSION 1.0.0
    DESCRIPTION "ThreatOne Enterprise Cybersecurity Platform"
    LANGUAGES CXX
)

# C++20 Standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile_commands.json for tooling
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Options
option(ENABLE_QT "Build with Qt6 support" OFF)
option(ENABLE_SANITIZERS "Enable address and undefined behavior sanitizers" OFF)
option(ENABLE_TESTING "Build unit tests" ON)

# Include CMake utility modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(CompilerOptions)
include(Version)
include(Dependencies)

if(ENABLE_QT)
    include(QtHelpers)
endif()

# Conditional Qt6
if(ENABLE_QT)
    find_package(Qt6 REQUIRED COMPONENTS
        Core
        Quick
        Widgets
        Network
        Sql
        WebSockets
        Charts
        Quick3D
    )
    qt_standard_project_setup()
endif()

# Source modules - order matters for dependencies
add_subdirectory(src/utils)
add_subdirectory(src/core)
add_subdirectory(src/database)
add_subdirectory(src/network)
add_subdirectory(src/security)
add_subdirectory(src/ai)
add_subdirectory(src/scanner)
add_subdirectory(src/monitor)
add_subdirectory(src/firewall)
add_subdirectory(src/sandbox)
add_subdirectory(src/hids)
add_subdirectory(src/edr)
add_subdirectory(src/xdr)
add_subdirectory(src/siem)
add_subdirectory(src/soc)
add_subdirectory(src/vulnerability)
add_subdirectory(src/compliance)
add_subdirectory(src/identity)
add_subdirectory(src/cloud)
add_subdirectory(src/reporting)
add_subdirectory(src/analytics)
add_subdirectory(src/licensing)
add_subdirectory(src/telemetry)
add_subdirectory(src/updates)
add_subdirectory(src/plugin)
add_subdirectory(src/app)

# Testing
if(ENABLE_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()
