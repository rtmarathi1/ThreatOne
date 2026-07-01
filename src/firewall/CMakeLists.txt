add_library(threatone_firewall STATIC
    src/placeholder.cpp
)

target_include_directories(threatone_firewall
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_firewall
    PUBLIC
        threatone_compiler_options
        threatone_core
)
