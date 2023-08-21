# ==============================================================================
# CMake project definitions
# ==============================================================================
cmake_minimum_required(VERSION 3.16.0)
project(ot-efr32 VERSION 1.0.0)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)

# Toolchain file
message(STATUS "Toolchain file: ${CMAKE_TOOLCHAIN_FILE}")

# ==============================================================================
# OpenThread
# ==============================================================================
include(${PROJECT_SOURCE_DIR}/openthread/etc/cmake/functions.cmake)

# Package Version
set(OT_PACKAGE_VERSION "" CACHE STRING "OpenThread Package Version")
if(OT_PACKAGE_VERSION STREQUAL "")
    ot_git_version(OT_PACKAGE_VERSION)
    message(STATUS "Setting default package version: ${OT_PACKAGE_VERSION}")
endif()
message(STATUS "Package Version: ${OT_PACKAGE_VERSION}")


# NOTE: The "openthread" subdirectory needs to be added after all OT_* variables are defined
add_subdirectory(openthread)

add_subdirectory(./platform/src)

target_compile_options(ot-config INTERFACE
    -Wno-shadow
    -Wno-pedantic
)

message("OT_RCP     = ${OT_RCP}")
message("OT_FTD     = ${OT_FTD}")
message("OT_MTD     = ${OT_MTD}")
message("OT_APP_RCP = ${OT_APP_RCP}")
message("OT_APP_NCP = ${OT_APP_NCP}")
message("OT_APP_CLI = ${OT_APP_CLI}")
