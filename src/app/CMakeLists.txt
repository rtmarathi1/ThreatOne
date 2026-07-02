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
    # ViewModel headers are listed explicitly so Qt's AUTOMOC processes their
    # Q_OBJECT macros. They live in a different directory tree than the .cpp
    # files, so AUTOMOC's same-basename heuristic would otherwise miss them,
    # causing unresolved metaObject/qt_metacast/staticMetaObject/signal symbols.
    include/app/viewmodels/DashboardViewModel.h
    include/app/viewmodels/ScannerViewModel.h
    include/app/viewmodels/FirewallViewModel.h
    include/app/viewmodels/EDRViewModel.h
    include/app/viewmodels/IncidentViewModel.h
    include/app/viewmodels/AssetViewModel.h
    include/app/viewmodels/ThreatIntelViewModel.h
    include/app/viewmodels/ReportViewModel.h
    include/app/viewmodels/SettingsViewModel.h
    include/app/viewmodels/UsersViewModel.h
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

    # QML is bundled via a classic Qt resource (qml.qrc). Every .qml file (and the
    # themes/widgets qmldir files) is aliased under "qml/..." so the runtime paths
    # are exactly "qrc:/qml/main.qml" etc. - matching the URL loaded by
    # QQmlApplicationEngine in main.cpp and the relative directory imports used by
    # the QML files. AUTORCC compiles the .qrc into the target automatically.
    #
    # NOTE: we deliberately do NOT use qt_add_qml_module here. That macro exposes
    # resources under "qrc:/<URI>/..." (e.g. qrc:/ThreatOne/...), which would not
    # match the "qrc:/qml/..." URL the engine loads, so the window would never
    # appear. The classic .qrc approach guarantees the paths line up. The C++
    # ViewModel types are still registered via qmlRegisterType() in main.cpp under
    # the "ThreatOne.ViewModels" URI, independent of this file resource.
    set(CMAKE_AUTORCC ON)
    target_sources(threatone_app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/qml.qrc)
endif()

# Windows version resource: populates the executable's file properties
# (Details tab). Handled automatically by the RC compiler under MSVC/Ninja and
# has no effect on non-Windows builds.
if(WIN32)
    target_sources(threatone_app PRIVATE resources/threatone.rc)
endif()

set_target_properties(threatone_app PROPERTIES
    OUTPUT_NAME "threatone"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
