# CompilerOptions.cmake - Compiler flags and sanitizer configuration

# Create an interface library for compiler options
add_library(threatone_compiler_options INTERFACE)

# Compiler warnings
target_compile_options(threatone_compiler_options INTERFACE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
        -Wcast-align
        -Wunused
        -Wnull-dereference
        -Wdouble-promotion
        -Wformat=2
        -Wimplicit-fallthrough
    >
    $<$<CXX_COMPILER_ID:MSVC>:
        /W4
        /permissive-
    >
)

# Sanitizers
if(ENABLE_SANITIZERS)
    target_compile_options(threatone_compiler_options INTERFACE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:
            -fsanitize=address,undefined
            -fno-omit-frame-pointer
        >
    )
    target_link_options(threatone_compiler_options INTERFACE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:
            -fsanitize=address,undefined
        >
    )
endif()

# Position-independent code for shared libraries
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
