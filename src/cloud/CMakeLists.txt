find_package(Threads REQUIRED)

add_library(threatone_cloud STATIC
    src/CloudManager.cpp
    src/CloudSyncService.cpp
    src/BackupManager.cpp
    src/CloudPolicyManager.cpp
    src/DeviceManager.cpp
    src/RemoteScanService.cpp
    src/CloudAssetDiscovery.cpp
)

target_include_directories(threatone_cloud
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_cloud
    PUBLIC
        threatone_compiler_options
        threatone_core
        nlohmann_json
        Threads::Threads
)
