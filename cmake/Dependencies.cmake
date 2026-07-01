# Dependencies.cmake - Third-party library management

# Base path for vendored third-party libraries
set(THIRD_PARTY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party")

# Optional external library integrations (all default OFF)
option(ENABLE_OPENSSL "Enable OpenSSL for cryptographic operations" OFF)
option(ENABLE_YARA "Enable YARA library for rule-based scanning" OFF)
option(ENABLE_LIBSODIUM "Enable libsodium for authenticated encryption" OFF)
option(ENABLE_ZSTD "Enable Zstandard for compression" OFF)

# Add custom find module path
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# OpenSSL integration
if(ENABLE_OPENSSL)
    find_package(OpenSSL)
    if(OpenSSL_FOUND)
        add_compile_definitions(HAS_OPENSSL)
        message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
    else()
        message(WARNING "ENABLE_OPENSSL is ON but OpenSSL was not found. Falling back to built-in implementations.")
    endif()
endif()

# YARA integration
if(ENABLE_YARA)
    find_package(YARA)
    if(YARA_FOUND)
        add_compile_definitions(HAS_YARA)
        message(STATUS "YARA found: ${YARA_LIBRARIES}")
    else()
        message(WARNING "ENABLE_YARA is ON but YARA was not found. Falling back to built-in implementation.")
    endif()
endif()

# libsodium integration
if(ENABLE_LIBSODIUM)
    find_package(Libsodium)
    if(LIBSODIUM_FOUND)
        add_compile_definitions(HAS_LIBSODIUM)
        message(STATUS "libsodium found: ${LIBSODIUM_LIBRARIES}")
    else()
        message(WARNING "ENABLE_LIBSODIUM is ON but libsodium was not found. Falling back to built-in implementation.")
    endif()
endif()

# Zstandard integration
if(ENABLE_ZSTD)
    find_package(zstd CONFIG QUIET)
    if(NOT zstd_FOUND)
        # Try pkg-config as fallback
        find_library(ZSTD_LIBRARY NAMES zstd libzstd)
        find_path(ZSTD_INCLUDE_DIR NAMES zstd.h)
        if(ZSTD_LIBRARY AND ZSTD_INCLUDE_DIR)
            set(ZSTD_FOUND TRUE)
        endif()
    else()
        set(ZSTD_FOUND TRUE)
    endif()

    if(ZSTD_FOUND)
        add_compile_definitions(HAS_ZSTD)
        message(STATUS "Zstandard found")
    else()
        message(WARNING "ENABLE_ZSTD is ON but zstd was not found. Falling back to passthrough implementation.")
    endif()
endif()

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

# SQLite3 - embedded SQL database engine
add_library(sqlite3 STATIC
    "${THIRD_PARTY_DIR}/sqlite/src/sqlite3_stub.cpp"
)
target_include_directories(sqlite3 PUBLIC
    "${THIRD_PARTY_DIR}/sqlite/include"
)
