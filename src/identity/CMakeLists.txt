add_library(threatone_identity STATIC
    src/IdentityManager.cpp
)

target_include_directories(threatone_identity
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_identity
    PUBLIC
        threatone_compiler_options
        threatone_core
)
