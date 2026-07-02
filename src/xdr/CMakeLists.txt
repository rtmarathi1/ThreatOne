find_package(Threads REQUIRED)

add_library(threatone_xdr STATIC
    src/XDREngine.cpp
    src/EndpointCorrelation.cpp
    src/NetworkCorrelation.cpp
    src/EmailCorrelation.cpp
    src/CloudCorrelation.cpp
    src/IdentityCorrelation.cpp
    src/AutomatedInvestigation.cpp
    src/ThreatHunting.cpp
    src/ResponseOrchestrator.cpp
)

target_include_directories(threatone_xdr
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_xdr
    PUBLIC
        threatone_compiler_options
        threatone_core
        Threads::Threads
)
