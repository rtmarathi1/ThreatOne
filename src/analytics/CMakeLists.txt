find_package(Threads REQUIRED)

add_library(threatone_analytics STATIC
    src/AnalyticsEngine.cpp
    src/BehaviorAnalyticsEngine.cpp
)

target_include_directories(threatone_analytics
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_analytics
    PUBLIC
        threatone_compiler_options
        threatone_core
        nlohmann_json
        Threads::Threads
)
