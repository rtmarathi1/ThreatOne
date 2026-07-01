# QtHelpers.cmake - Qt-related macros and utilities
# Only included when ENABLE_QT=ON

if(NOT ENABLE_QT)
    return()
endif()

# Macro to register a QML module
macro(threatone_add_qml_module TARGET)
    cmake_parse_arguments(ARG "" "URI;VERSION" "QML_FILES;SOURCES" ${ARGN})

    qt_add_qml_module(${TARGET}
        URI ${ARG_URI}
        VERSION ${ARG_VERSION}
        QML_FILES ${ARG_QML_FILES}
        SOURCES ${ARG_SOURCES}
    )
endmacro()

# Macro to add Qt resources
macro(threatone_add_resources TARGET)
    cmake_parse_arguments(ARG "" "PREFIX" "FILES" ${ARGN})

    qt_add_resources(${TARGET} "${TARGET}_resources"
        PREFIX ${ARG_PREFIX}
        FILES ${ARG_FILES}
    )
endmacro()

# Auto-enable MOC, UIC, RCC for Qt targets
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)
