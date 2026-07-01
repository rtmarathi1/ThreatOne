# FindYARA.cmake - Find the YARA library
#
# This module defines:
#   YARA_FOUND        - True if YARA was found
#   YARA_INCLUDE_DIRS - YARA include directories
#   YARA_LIBRARIES    - YARA libraries to link against

find_path(YARA_INCLUDE_DIR
    NAMES yara.h
    PATHS
        /usr/include
        /usr/local/include
        /opt/local/include
        ${YARA_ROOT}/include
    PATH_SUFFIXES yara
)

find_library(YARA_LIBRARY
    NAMES yara libyara
    PATHS
        /usr/lib
        /usr/local/lib
        /opt/local/lib
        ${YARA_ROOT}/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(YARA
    REQUIRED_VARS YARA_LIBRARY YARA_INCLUDE_DIR
)

if(YARA_FOUND)
    set(YARA_INCLUDE_DIRS ${YARA_INCLUDE_DIR})
    set(YARA_LIBRARIES ${YARA_LIBRARY})
endif()

mark_as_advanced(YARA_INCLUDE_DIR YARA_LIBRARY)
