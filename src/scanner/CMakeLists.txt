add_library(threatone_scanner STATIC
    src/ScanEngine.cpp
)

target_include_directories(threatone_scanner
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_scanner
    PUBLIC
        threatone_compiler_options
        threatone_core
)
