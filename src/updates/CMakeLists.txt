add_library(threatone_updates STATIC
    src/UpdateManager.cpp
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
)
