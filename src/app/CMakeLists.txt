add_executable(threatone_app
    src/main.cpp
    src/AppController.cpp
)

target_include_directories(threatone_app
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_app
    PRIVATE
        threatone_compiler_options
        threatone_core
        threatone_database
        threatone_network
        threatone_security
        threatone_ai
        threatone_scanner
        threatone_monitor
        threatone_firewall
        threatone_sandbox
        threatone_hids
        threatone_edr
        threatone_xdr
        threatone_siem
        threatone_soc
        threatone_vulnerability
        threatone_compliance
        threatone_identity
        threatone_cloud
        threatone_reporting
        threatone_analytics
        threatone_licensing
        threatone_telemetry
        threatone_updates
        threatone_plugin
        threatone_utils
)

set_target_properties(threatone_app PROPERTIES
    OUTPUT_NAME "threatone"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
