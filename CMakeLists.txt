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

# Suppress MSVC CRT security warnings (C4996) for portable POSIX-style calls
if(MSVC)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
endif()

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

include(Platform)

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
add_subdirectory(src/threat_intel)
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
add_subdirectory(src/fleet)
add_subdirectory(src/api)
add_subdirectory(src/platform)
add_subdirectory(src/app)

# Testing
if(ENABLE_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()

# Packaging (CPack)
option(ENABLE_PACKAGING "Enable CPack packaging support" OFF)
if(ENABLE_PACKAGING)
    set(CPACK_PACKAGE_NAME "ThreatOne")
    set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
    set(CPACK_PACKAGE_VENDOR "ThreatOne Security Inc")
    set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "ThreatOne Enterprise Cybersecurity Platform")
    set(CPACK_PACKAGE_DESCRIPTION "Enterprise-grade cybersecurity platform for threat detection, response, and compliance management.")
    set(CPACK_PACKAGE_HOMEPAGE_URL "https://www.threatone.io")
    set(CPACK_PACKAGE_CONTACT "support@threatone.io")
    set(CPACK_PACKAGE_INSTALL_DIRECTORY "ThreatOne")
    set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/installer/packages/com.threatone.core/meta/license.txt")

    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set(CPACK_GENERATOR "DEB;RPM")
        set(CPACK_DEBIAN_PACKAGE_MAINTAINER "ThreatOne Security Inc <support@threatone.io>")
        set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
        set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
        set(CPACK_RPM_PACKAGE_LICENSE "Apache-2.0")
        set(CPACK_RPM_PACKAGE_GROUP "Applications/Security")
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
        set(CPACK_GENERATOR "NSIS")
        set(CPACK_NSIS_DISPLAY_NAME "ThreatOne Enterprise")
        set(CPACK_NSIS_PACKAGE_NAME "ThreatOne Enterprise")
        set(CPACK_NSIS_HELP_LINK "https://www.threatone.io/support")
        set(CPACK_NSIS_URL_INFO_ABOUT "https://www.threatone.io")
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        set(CPACK_GENERATOR "DragNDrop")
        set(CPACK_DMG_VOLUME_NAME "ThreatOne Enterprise")
        set(CPACK_BUNDLE_NAME "ThreatOne Enterprise")
        set(CPACK_BUNDLE_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/installer/macos/Info.plist.in")
    endif()

    include(CPack)
endif()
