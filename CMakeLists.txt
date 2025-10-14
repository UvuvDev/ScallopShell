cmake_minimum_required(VERSION 3.15)
project(scallop LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Default to Debug if not set by caller
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

# --- FTXUI ---
include(FetchContent)
FetchContent_Declare(
  ftxui
  GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI
  GIT_TAG        v6.1.9
)
FetchContent_MakeAvailable(ftxui)

# Uncomment if you also want CLI11 (header-only)
# FetchContent_Declare(
#   CLI11
#   GIT_REPOSITORY https://github.com/CLIUtils/CLI11
#   GIT_TAG        v2.4.2
# )
# FetchContent_MakeAvailable(CLI11)

# --- Sources ---
# Pull in everything under src/, including your UI file(s)
file(GLOB_RECURSE SCALLOP_SOURCES
     CONFIGURE_DEPENDS
     "${CMAKE_SOURCE_DIR}/src/*.cpp")

add_executable(scallop ${SCALLOP_SOURCES})

# --- Includes ---
target_include_directories(scallop PRIVATE
  ${CMAKE_SOURCE_DIR}/include

)

# --- Capstone ---
find_library(CAPSTONE_LIB capstone REQUIRED)

# --- Threads (FTXUI uses std::thread; link pthread on Linux) ---
find_package(Threads REQUIRED)

# --- Link ---
target_link_libraries(scallop PRIVATE
  ftxui::component
  ftxui::dom
  ftxui::screen
  ${CAPSTONE_LIB}
  Threads::Threads
  # CLI11::CLI11      # uncomment if you enabled CLI11 above
)

# Helpful warnings (optional)
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(scallop PRIVATE -Wall -Wextra -Wpedantic)
endif()
