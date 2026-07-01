add_library(threatone_utils STATIC
    src/Utils.cpp
    src/CompressionUtils.cpp
)

target_include_directories(threatone_utils
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../core/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(threatone_utils
    PUBLIC
        threatone_compiler_options
        spdlog
        nlohmann_json
)

# Conditionally link OpenSSL for CryptoUtils
if(ENABLE_OPENSSL AND OpenSSL_FOUND)
    target_link_libraries(threatone_utils PUBLIC OpenSSL::Crypto)
    target_compile_definitions(threatone_utils PUBLIC HAS_OPENSSL)
endif()

# Conditionally link libsodium for CryptoUtils
if(ENABLE_LIBSODIUM AND LIBSODIUM_FOUND)
    target_include_directories(threatone_utils PUBLIC ${LIBSODIUM_INCLUDE_DIRS})
    target_link_libraries(threatone_utils PUBLIC ${LIBSODIUM_LIBRARIES})
    target_compile_definitions(threatone_utils PUBLIC HAS_LIBSODIUM)
endif()

# Conditionally link zstd for CompressionUtils
if(ENABLE_ZSTD AND ZSTD_FOUND)
    if(TARGET zstd::libzstd_shared OR TARGET zstd::libzstd_static)
        if(TARGET zstd::libzstd_static)
            target_link_libraries(threatone_utils PUBLIC zstd::libzstd_static)
        else()
            target_link_libraries(threatone_utils PUBLIC zstd::libzstd_shared)
        endif()
    else()
        target_include_directories(threatone_utils PUBLIC ${ZSTD_INCLUDE_DIR})
        target_link_libraries(threatone_utils PUBLIC ${ZSTD_LIBRARY})
    endif()
    target_compile_definitions(threatone_utils PUBLIC HAS_ZSTD)
endif()
