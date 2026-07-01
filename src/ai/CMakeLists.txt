add_library(threatone_ai STATIC
    src/AIEngine.cpp
)

target_include_directories(threatone_ai
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_ai
    PUBLIC
        threatone_compiler_options
        threatone_core
)
