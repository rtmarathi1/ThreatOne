# FindLibsodium.cmake - Find the libsodium library
#
# This module defines:
#   LIBSODIUM_FOUND        - True if libsodium was found
#   LIBSODIUM_INCLUDE_DIRS - libsodium include directories
#   LIBSODIUM_LIBRARIES    - libsodium libraries to link against

find_path(LIBSODIUM_INCLUDE_DIR
    NAMES sodium.h
    PATHS
        /usr/include
        /usr/local/include
        /opt/local/include
        ${LIBSODIUM_ROOT}/include
)

find_library(LIBSODIUM_LIBRARY
    NAMES sodium libsodium
    PATHS
        /usr/lib
        /usr/local/lib
        /opt/local/lib
        ${LIBSODIUM_ROOT}/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libsodium
    REQUIRED_VARS LIBSODIUM_LIBRARY LIBSODIUM_INCLUDE_DIR
)

if(LIBSODIUM_FOUND)
    set(LIBSODIUM_INCLUDE_DIRS ${LIBSODIUM_INCLUDE_DIR})
    set(LIBSODIUM_LIBRARIES ${LIBSODIUM_LIBRARY})
endif()

mark_as_advanced(LIBSODIUM_INCLUDE_DIR LIBSODIUM_LIBRARY)
