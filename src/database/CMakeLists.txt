add_library(threatone_database STATIC
    src/ConnectionManager.cpp
    src/Migration.cpp
    src/Model.cpp
    src/QueryBuilder.cpp
    src/Schema.cpp
    src/models/Scan.cpp
    src/models/Threat.cpp
    src/models/User.cpp
    src/models/Alert.cpp
    src/models/Asset.cpp
    src/models/FirewallRule.cpp
    src/models/Incident.cpp
    src/models/License.cpp
    src/models/Policy.cpp
    src/models/Setting.cpp
    src/models/Vulnerability.cpp
)

target_include_directories(threatone_database
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_database
    PUBLIC
        threatone_compiler_options
        threatone_core
        sqlite3
        nlohmann_json
)
