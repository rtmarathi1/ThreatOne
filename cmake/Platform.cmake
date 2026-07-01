# Platform.cmake - OS detection and platform-specific configuration

# Detect operating system
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(THREATONE_PLATFORM_LINUX TRUE)
    set(THREATONE_PLATFORM_NAME "Linux")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(THREATONE_PLATFORM_WINDOWS TRUE)
    set(THREATONE_PLATFORM_NAME "Windows")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(THREATONE_PLATFORM_MACOS TRUE)
    set(THREATONE_PLATFORM_NAME "macOS")
else()
    set(THREATONE_PLATFORM_UNKNOWN TRUE)
    set(THREATONE_PLATFORM_NAME "Unknown")
endif()

message(STATUS "ThreatOne platform: ${THREATONE_PLATFORM_NAME}")

# Platform drivers option - requires platform-specific APIs at runtime
option(ENABLE_PLATFORM_DRIVERS "Enable platform-specific drivers (file monitoring, network filtering, process monitoring)" OFF)

if(ENABLE_PLATFORM_DRIVERS)
    message(STATUS "Platform drivers: ENABLED")
else()
    message(STATUS "Platform drivers: DISABLED (stub implementations)")
endif()
