add_executable(threatone_app
    src/main.cpp
    src/AppController.cpp
    src/viewmodels/DashboardViewModel.cpp
    src/viewmodels/ScannerViewModel.cpp
    src/viewmodels/FirewallViewModel.cpp
    src/viewmodels/EDRViewModel.cpp
    src/viewmodels/IncidentViewModel.cpp
    src/viewmodels/AssetViewModel.cpp
    src/viewmodels/ThreatIntelViewModel.cpp
    src/viewmodels/ReportViewModel.cpp
    src/viewmodels/SettingsViewModel.cpp
    src/viewmodels/UsersViewModel.cpp
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
        threatone_platform
)

if(ENABLE_QT)
    target_link_libraries(threatone_app
        PRIVATE
            Qt6::Core
            Qt6::Quick
            Qt6::Widgets
    )

    target_compile_definitions(threatone_app PRIVATE ENABLE_QT_BUILD)

    # Collect QML files for the module
    file(GLOB_RECURSE QML_FILES "${CMAKE_SOURCE_DIR}/qml/*.qml")

    qt_add_qml_module(threatone_app
        URI ThreatOne
        VERSION 1.0
        QML_FILES ${QML_FILES}
    )
endif()

set_target_properties(threatone_app PROPERTIES
    OUTPUT_NAME "threatone"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
