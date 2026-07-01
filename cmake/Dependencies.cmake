# Dependencies.cmake - Third-party library management

# Base path for vendored third-party libraries
set(THIRD_PARTY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party")

# spdlog - header-only logging library
add_library(spdlog INTERFACE)
target_include_directories(spdlog INTERFACE
    "${THIRD_PARTY_DIR}/spdlog/include"
)

# nlohmann/json - header-only JSON library
add_library(nlohmann_json INTERFACE)
target_include_directories(nlohmann_json INTERFACE
    "${THIRD_PARTY_DIR}/nlohmann/include"
)

# doctest - header-only test framework
add_library(doctest INTERFACE)
target_include_directories(doctest INTERFACE
    "${THIRD_PARTY_DIR}/doctest/include"
)

# SQLite3 - stub library for compilation (replace with real amalgamation in production)
add_library(sqlite3 STATIC
    "${THIRD_PARTY_DIR}/sqlite/src/sqlite3_stub.cpp"
)
target_include_directories(sqlite3 PUBLIC
    "${THIRD_PARTY_DIR}/sqlite/include"
)
