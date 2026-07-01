add_library(threatone_network STATIC
    src/NetworkManager.cpp
    src/IPBlocklist.cpp
    src/GeoIPDatabase.cpp
    src/DNSFilter.cpp
    src/BandwidthMonitor.cpp
    src/IntrusionDetector.cpp
    src/NetworkIsolation.cpp
    src/ConnectionLogger.cpp
    src/ApplicationControl.cpp
)

target_include_directories(threatone_network
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_network
    PUBLIC
        threatone_compiler_options
        threatone_core
        nlohmann_json
)
