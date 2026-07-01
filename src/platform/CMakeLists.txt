set(PLATFORM_SOURCES
    src/PlatformFactory.cpp
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND PLATFORM_SOURCES src/LinuxDriver.cpp)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    list(APPEND PLATFORM_SOURCES src/WindowsDriver.cpp)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    list(APPEND PLATFORM_SOURCES src/MacOSDriver.cpp)
endif()

add_library(threatone_platform STATIC ${PLATFORM_SOURCES})

target_include_directories(threatone_platform
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_platform
    PUBLIC
        threatone_compiler_options
        threatone_core
)

if(ENABLE_PLATFORM_DRIVERS)
    target_compile_definitions(threatone_platform PRIVATE ENABLE_PLATFORM_DRIVERS)
endif()
