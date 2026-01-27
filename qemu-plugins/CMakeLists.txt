cmake_minimum_required(VERSION 3.16)

project(refactorscallop LANGUAGES C CXX)

# Position independent code is needed for a plugin .so
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# === QEMU paths (you MUST set these when configuring) ===
set(QEMU_SRC "" CACHE PATH "Path to the QEMU source tree")
set(QEMU_BUILD "" CACHE PATH "Path to the QEMU build tree (where you ran ./configure && make)")

if(NOT QEMU_SRC)
    message(FATAL_ERROR "QEMU_SRC is not set. Pass -DQEMU_SRC=/path/to/qemu to CMake.")
endif()

if(NOT QEMU_BUILD)
    message(FATAL_ERROR "QEMU_BUILD is not set. Pass -DQEMU_BUILD=/path/to/qemu/build to CMake.")
endif()

# === MinimalSocket via FetchContent ===
include(FetchContent)

# Disable MinimalSocket samples
set(BUILD_MinimalCppSocket_SAMPLES OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    min_sock
    GIT_REPOSITORY https://github.com/andreacasalino/Minimal-Socket
    GIT_TAG        master
)

FetchContent_MakeAvailable(min_sock)

# === Find glib-2.0 (like your pkg-config line) ===
find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB2 REQUIRED glib-2.0)

# === Sources ===
# C sources at top level (e.g. disasm.c)
file(GLOB PLUGIN_C_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/*.c"
)

# C++ sources at top level and in src/
file(GLOB PLUGIN_CPP_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
)

add_library(refactorscallop SHARED
    ${PLUGIN_C_SOURCES}
    ${PLUGIN_CPP_SOURCES}
)

# If you want a specific C++ standard
set_target_properties(refactorscallop PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
    OUTPUT_NAME "refactorscallop"  # produces librefactorscallop.so
)

# === Include directories ===
target_include_directories(refactorscallop
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${QEMU_SRC}/include
        ${QEMU_BUILD}/include
        ${GLIB2_INCLUDE_DIRS}
)

# Extra GLib flags (warnings, defines, etc.)
target_compile_options(refactorscallop PRIVATE ${GLIB2_CFLAGS_OTHER})

# === Linking ===
target_link_libraries(refactorscallop
    PRIVATE
        ${GLIB2_LIBRARIES}
        elf
        pthread
        MinimalSocket
)
