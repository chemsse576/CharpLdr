cmake_minimum_required(VERSION 3.20)
project(CharpLdr LANGUAGES CXX ASM_MASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Force x64
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "CharpLdr requires x64 build. Use -A x64")
endif()

# Source files
set(SOURCES
    src/main.cpp
    src/peb_walk.cpp
    src/syscalls.cpp
    src/stackspoof.cpp
    src/unhook.cpp
    src/amsi.cpp
    src/etw.cpp
    src/crypto.cpp
    src/network.cpp
    src/stomp.cpp
    src/clr.cpp
    src/threadpool.cpp
)

# ASM files (MASM) - kept at project root to avoid CMake/MASM path separator issues
set(ASM_SOURCES
    syscalls.asm
)

# Header files (for IDE visibility)
set(HEADERS
    src/hash.h
    src/obfstr.h
    src/peb_walk.h
    src/syscalls.h
    src/stackspoof.h
    src/unhook.h
    src/amsi.h
    src/etw.h
    src/crypto.h
    src/network.h
    src/stomp.h
    src/clr.h
    src/threadpool.h
)

add_executable(charpldr ${SOURCES} ${ASM_SOURCES} ${HEADERS} src/version.rc)

# Static CRT (/MT in Release, /MTd in Debug)
set_property(TARGET charpldr PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# C++ compiler flags only (not applied to MASM)
set_source_files_properties(${SOURCES} PROPERTIES
    COMPILE_FLAGS "/W4 /WX /O2 /GS- /EHsc"
)

# Preprocessor definitions
target_compile_definitions(charpldr PRIVATE
    _CRT_SECURE_NO_WARNINGS
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

# MASM flags
set_source_files_properties(${ASM_SOURCES} PROPERTIES
    LANGUAGE ASM_MASM
    COMPILE_FLAGS "/nologo /c /W3 /WX"
)

# Linker flags: strip Rich header, debug info, reproducible timestamps
target_link_options(charpldr PRIVATE
    /SUBSYSTEM:CONSOLE
    /EMITTOOLVERSIONINFO:NO
    /DEBUG:NONE
    /Brepro
    /PDBALTPATH:none
)

# Link libraries (minimal - most APIs resolved via PEB walk)
target_link_libraries(charpldr PRIVATE
    oleaut32
    ole32
    ws2_32
)

message(STATUS "CharpLdr v2 configuration:")
message(STATUS "  Platform: x64")
message(STATUS "  CRT: Static (/MT)")
message(STATUS "  Optimization: /O2")
message(STATUS "  Stack cookies: Disabled (/GS-)")
message(STATUS "  Rich header: Stripped")
message(STATUS "  Debug info: None")
