add_library(threatone_fleet STATIC
    src/FleetManager.cpp
    src/PolicyEngine.cpp
    src/RemoteManager.cpp
    src/DeploymentManager.cpp
)

target_include_directories(threatone_fleet
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_fleet
    PUBLIC
        threatone_compiler_options
        threatone_core
        nlohmann_json
)
