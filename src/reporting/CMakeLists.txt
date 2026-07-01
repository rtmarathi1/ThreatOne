add_library(threatone_reporting STATIC
    src/placeholder.cpp
)

target_include_directories(threatone_reporting
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_reporting
    PUBLIC
        threatone_compiler_options
        threatone_core
)
