add_library(threatone_security STATIC
    src/SecurityEngine.cpp
)

target_include_directories(threatone_security
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_security
    PUBLIC
        threatone_compiler_options
        threatone_core
        threatone_threat_intel
)
