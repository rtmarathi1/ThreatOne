find_package(Threads REQUIRED)

add_library(threatone_plugin STATIC
    src/PluginManager.cpp
    src/PluginSDK.cpp
    src/PluginSandbox.cpp
    src/PluginMarketplace.cpp
    src/DependencyResolver.cpp
    src/PluginPermissions.cpp
    src/PluginVersionManager.cpp
)

target_include_directories(threatone_plugin
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_plugin
    PUBLIC
        threatone_compiler_options
        threatone_core
        Threads::Threads
)
