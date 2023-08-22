###########################################################
# Copyright 2019 Virtru Corporation
#
# SPDX - License Identifier: BSD-3-Clause-Clear
#
# Sample application
###########################################################
cmake_minimum_required(VERSION 3.5)
project(tdf_sample)

# enable verbose logging
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 17)

# generate compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

#list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

# enable warning
if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    add_compile_options(-Wall -Wextra)
endif()

# set include and lib directories based on available dirs
if(EXISTS ${PROJECT_SOURCE_DIR}/../tdf-lib-cpp)
    set(SDKINCDIR ${PROJECT_SOURCE_DIR}/../tdf-lib-cpp/include)
    set(SDKLIBDIR ${PROJECT_SOURCE_DIR}/../tdf-lib-cpp/lib)
else()
    set(SDKINCDIR ${PROJECT_SOURCE_DIR}/../src/lib/include)
    set(SDKLIBDIR ${PROJECT_SOURCE_DIR}/../src/build/lib)
endif()

# windows-specific flags
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set(CMAKE_CXX_FLAGS_DEBUG "/Zi /Ob0 /Od /MDd")
    set(CMAKE_CXX_FLAGS_RELEASE "/MD")
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(OTHERLIBS pthread dl)
endif()

# Add gcov if code coverage is being done
if("$ENV{VBUILD_CODE_COVERAGE}" STREQUAL "true")
    set(OTHERLIBS ${OTHERLIBS} gcov)
endif()

find_package(opentdf-client CONFIG REQUIRED)

link_directories(
    ${SDKLIBDIR}
    ${CONAN_LIB_DIRS}
    )

link_libraries(
    opentdf_static
    ${OTHERLIBS}
    ${CONAN_LIBS}
    ${CONAN_SYSTEM_LIBS}
    )
    
include_directories(
    ${SDKINCDIR}
    )

target_link_libraries(${PROJECT_NAME} opentdf-client::opentdf-client)
add_executable(tdf_sample main.cpp)
