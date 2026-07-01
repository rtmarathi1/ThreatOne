add_library(threatone_soc STATIC
    src/placeholder.cpp
)

target_include_directories(threatone_soc
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_soc
    PUBLIC
        threatone_compiler_options
        threatone_core
)
