add_library(threatone_xdr STATIC
    src/placeholder.cpp
)

target_include_directories(threatone_xdr
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_xdr
    PUBLIC
        threatone_compiler_options
        threatone_core
)
