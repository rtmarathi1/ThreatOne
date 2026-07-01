add_library(threatone_cloud STATIC
    src/CloudManager.cpp
)

target_include_directories(threatone_cloud
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_cloud
    PUBLIC
        threatone_compiler_options
        threatone_core
)
