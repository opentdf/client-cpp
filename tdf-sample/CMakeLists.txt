###########################################################
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

link_directories(
    ${PROJECT_SOURCE_DIR}/../tdf-lib-cpp/lib
    )

link_libraries(
    opentdf_static_combined
    ${OTHERLIBS}
    )
    
include_directories(
    ${PROJECT_SOURCE_DIR}/../tdf-lib-cpp/include
    )

add_executable(tdf_sample main.cpp)
    
