add_library(threatone_reporting STATIC
    src/ReportEngine.cpp
    src/ReportGenerator.cpp
    src/ReportTemplate.cpp
    src/ExportEngine.cpp
    src/ReportScheduler.cpp
    src/ReportStorage.cpp
)

target_include_directories(threatone_reporting
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_reporting
    PUBLIC
        threatone_compiler_options
        threatone_core
    PRIVATE
        nlohmann_json
)
