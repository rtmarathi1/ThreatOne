add_library(threatone_core STATIC
    src/Application.cpp
    src/Config.cpp
    src/EventBus.cpp
    src/Logger.cpp
    src/PluginLoader.cpp
    src/ServiceLocator.cpp
)

target_include_directories(threatone_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_core
    PUBLIC
        threatone_compiler_options
        threatone_utils
        spdlog
        nlohmann_json
        threatone_version
)
