add_library(threatone_api STATIC
    src/Router.cpp
    src/Controllers.cpp
    src/ApiAuth.cpp
    src/WebhookManager.cpp
)

target_include_directories(threatone_api
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_api
    PUBLIC
        threatone_compiler_options
        threatone_core
        nlohmann_json
)
