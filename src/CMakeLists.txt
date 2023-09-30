# Copyright 2019 Virtru Corporation
#
# SPDX - License Identifier: BSD-3-Clause-Clear
#
cmake_minimum_required (VERSION 3.8)

project(tdf-client)

# enable verbose logging
set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_CXX_STANDARD 17)

# generate compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# windows-specific flags
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DBOOST_ALL_NO_LIB -D_WIN32_WINNT=0x0A00 -D_SILENCE_CXX17_ALLOCATOR_VOID_DEPRECATION_WARNING=1")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DWIN32_LEAN_AND_MEAN")
    set(CMAKE_CXX_FLAGS_DEBUG "/Zi /Ob0 /Od -D_ITERATOR_DEBUG_LEVEL=2 /MDd")
    set(CMAKE_CXX_FLAGS_RELEASE "/MD")
    set(CMAKE_STATIC_LINKER_FLAGS "${CMAKE_STATIC_LINKER_FLAGS} /ignore:4099")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /ignore:4099")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /ignore:4099")
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DJSON_HAS_CPP_14=1")
endif()

if(EXISTS "${CMAKE_BINARY_DIR}/conanbuildinfo.cmake")
  include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
endif()

option(ENABLE_CLANG_TIDY "Enable checking with clang-tidy" FALSE)

if(ENABLE_CLANG_TIDY)
  find_program(CLANGTIDY clang-tidy)
  if(CLANGTIDY)
    set(CMAKE_CXX_CLANG_TIDY ${CLANGTIDY})
  else()
    message(SEND_ERROR "clang-tidy executable not found")
  endif()
endif()

set(VIRTRU_SDK_BUILD_ARCH "x86_64")
if (DEFINED ENV{VIRTRU_SDK_BUILD_ARCH})
    set(VIRTRU_SDK_BUILD_ARCH $ENV{VIRTRU_SDK_BUILD_ARCH})
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux" AND ${VIRTRU_SDK_BUILD_ARCH} MATCHES "x86_64")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DFIPS_BUILD=1")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-O0)
else()
    add_compile_options(-O3)
endif()

# Build the tdf library.
add_subdirectory(lib)

if (DEFINED ENV{VBUILD_UNIT_TESTS})
  if("$ENV{VBUILD_UNIT_TESTS}" MATCHES "true")
    # Build unit tests.
    enable_testing()
    add_subdirectory(tests)
  else()
    message(STATUS "Skipping unit tests because of environment value: ${VBUILD_UNIT_TESTS}")
  endif()
else()
    message(STATUS "Skipping unit tests by default")
    set(VBUILD_UNIT_TESTS "false")
endif()

# Dump test failure logs to console to aid with debugging failures
list(APPEND CMAKE_CTEST_ARGUMENTS "--output-on-failure")
