add_library(threatone_utils STATIC
    src/Utils.cpp
)

target_include_directories(threatone_utils
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_utils
    PUBLIC
        threatone_compiler_options
        spdlog
        nlohmann_json
)
