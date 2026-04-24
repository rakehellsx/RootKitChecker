cmake_minimum_required(VERSION 3.14)
project(memscope VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# -----------------------------------------------------------------------
# Build type
# -----------------------------------------------------------------------
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# -----------------------------------------------------------------------
# Compiler flags
# -----------------------------------------------------------------------
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_C_FLAGS_DEBUG   "-g -O0 -DDEBUG")

add_compile_options(
    -Wall
    -Wextra
    -Wno-unused-parameter
    -Wno-sign-compare
)

# -----------------------------------------------------------------------
# Source files
# -----------------------------------------------------------------------
set(SOURCES
    src/main.c
    src/py_bridge.c
    src/windows_scan.c
    src/linux_scan.c
    src/json_output.c
    third_party/cjson/cJSON.c
)

# -----------------------------------------------------------------------
# Include directories
# -----------------------------------------------------------------------
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/third_party/cjson
)

# -----------------------------------------------------------------------
# Executable
# -----------------------------------------------------------------------
add_executable(memscope ${SOURCES})

# -----------------------------------------------------------------------
# Link math library (required by cJSON on some platforms)
# -----------------------------------------------------------------------
target_link_libraries(memscope m)

# -----------------------------------------------------------------------
# Install
# -----------------------------------------------------------------------
install(TARGETS memscope DESTINATION bin)
install(PROGRAMS scripts/vol_runner.py DESTINATION share/memscope/scripts)

# -----------------------------------------------------------------------
# Print summary
# -----------------------------------------------------------------------
message(STATUS "")
message(STATUS "=== memscope build configuration ===")
message(STATUS "  Version     : ${PROJECT_VERSION}")
message(STATUS "  Install dir : ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  Build type  : ${CMAKE_BUILD_TYPE}")
message(STATUS "=====================================")
message(STATUS "")
message(STATUS "After building, set MEMSCOPE_VENV to your volatility3")
message(STATUS "virtualenv path, or use -v <venv_path> on the command line.")
message(STATUS "")
