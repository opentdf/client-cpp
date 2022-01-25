# Copyright 2019 Virtru Corporation
#
# SPDX - License - Identifier: MIT
#
cmake_minimum_required (VERSION 3.8)

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

if (DEFINED ENV{VBUILD_JAVA_BINDINGS})
    set(VBUILD_JAVA_BINDINGS $ENV{VBUILD_JAVA_BINDINGS})
    if (${VBUILD_JAVA_BINDINGS} MATCHES "true")
        message(STATUS "java bindings enabled via environment variable")
    else()
        message(STATUS "Skipping java bindings because of environment value: ${VBUILD_JAVA_BINDINGS}")
    endif()
else()
    message(STATUS "Skipping build of java bindings")
    set(VBUILD_JAVA_BINDINGS "false")
endif()

if (DEFINED ENV{VBUILD_CSHARP_BINDINGS})
    set(VBUILD_CSHARP_BINDINGS $ENV{VBUILD_CSHARP_BINDINGS})
    if (${VBUILD_CSHARP_BINDINGS} MATCHES "true")
        message(STATUS "csharp bindings enabled via environment variable")
    else()
        message(STATUS "Skipping csharp bindings because of environment value: ${VBUILD_CSHARP_BINDINGS}")
    endif()
else()
    message(STATUS "Skipping build of csharp bindings")
    set(VBUILD_CSHARP_BINDINGS "false")
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux" AND ${VIRTRU_SDK_BUILD_ARCH} MATCHES "x86_64")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DFIPS_BUILD=1")
endif()

# Build the tdf library.
add_subdirectory(lib)

if (DEFINED ENV{VBUILD_PYTHON_BINDINGS})
    set(VBUILD_PYTHON_BINDINGS $ENV{VBUILD_PYTHON_BINDINGS})
    if (${VBUILD_PYTHON_BINDINGS} MATCHES "true")
        message(STATUS "python bindings enabled via environment variable")
    else()
        message(STATUS "Skipping python bindings because of environment value: ${VBUILD_PYTHON_BINDINGS}")
    endif()
else()
    message(STATUS "Skipping build of python bindings")
    set(VBUILD_PYTHON_BINDINGS "false")
endif()

if(${VBUILD_PYTHON_BINDINGS} MATCHES "true")
   add_subdirectory(python-bindings)
endif()

if(${VBUILD_JAVA_BINDINGS} MATCHES "true")
   add_subdirectory(java-bindings)
endif()

if(${VBUILD_CSHARP_BINDINGS} MATCHES "true")
   add_subdirectory(csharp-bindings)
endif()

if("$ENV{VBUILD_UNIT_TESTS}" MATCHES "true")
  # Build unit tests.
  enable_testing()
  add_subdirectory(tests)
endif()

if("$ENV{VIRTRU_RUN_E2E_TESTS}" STREQUAL "true")
    add_subdirectory(e2e-tests)
endif()
# Dump test failure logs to console to aid with debugging failures
list(APPEND CMAKE_CTEST_ARGUMENTS "--output-on-failure")
