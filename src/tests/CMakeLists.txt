###########################################################
# Unit tests
###########################################################
cmake_minimum_required(VERSION 3.8)

project(tdf-test)

# enable verbose logging
set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_CXX_STANDARD 17)

# generate compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)

# enable warning
if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    add_compile_options(-Wall -Wextra -fPIC)
    if(DEFINED ENV{VBUILD_ADD_MACOS_FLAGS})
      if($ENV{VBUILD_ADD_MACOS_FLAGS} MATCHES "true")
        add_compile_options(-Wno-string-plus-int)
        add_compile_options(-Wno-deprecated-declarations)
      endif()
    endif()
    if(DEFINED ENV{VBUILD_ADD_RPI_FLAGS})
      if($ENV{VBUILD_ADD_RPI_FLAGS} MATCHES "true")
        add_compile_options(-mfloat-abi=hard -mfpu=vfpv2)
      endif()
    endif()
endif()

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DJSON_HAS_CPP_14=1")
    set(OTHERLIBS pthread dl rt)
endif()

# Add gcov if code coverage is being performed
if("$ENV{VBUILD_CODE_COVERAGE}" STREQUAL "true")
    set(OTHERLIBS ${OTHERLIBS} gcov)
endif()

set(VIRTRU_SDK_BUILD_ARCH "x86_64")
if (DEFINED ENV{VIRTRU_SDK_BUILD_ARCH})
    set(VIRTRU_SDK_BUILD_ARCH $ENV{VIRTRU_SDK_BUILD_ARCH})
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux" AND ${VIRTRU_SDK_BUILD_ARCH} MATCHES "x86_64")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DFIPS_BUILD=1")
endif()

# Include paths
include_directories(
    ${PROJECT_SOURCE_DIR}/../lib/include
    ${PROJECT_SOURCE_DIR}/../lib/src
    ${PROJECT_SOURCE_DIR}/../lib/src/crypto
    ${PROJECT_SOURCE_DIR}/../thirdparty-libs/common
    ${PROJECT_SOURCE_DIR}/../test/support
    ${CONAN_INCLUDE_DIRS}
    )

# set link info
link_directories(
    ${PROJECT_SOURCE_DIR}/../build/lib
    )

link_libraries(
    opentdf_static_combined
    ${OTHERLIBS}
    )

# Collect all the files from the test dir
file(GLOB TEST_SRCS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp)

file(GLOB SUPPORT_SRCS "support/*.cpp")

# Run the leaks check if the valgrind is installed.
set(CMAKE_VALGRIND_FOUND OFF)
find_program(MEMORYCHECK_COMMAND valgrind)
if (MEMORYCHECK_COMMAND AND ${VIRTRU_SDK_BUILD_ARCH} MATCHES "x86_64")
    set(CMAKE_VALGRIND_FOUND ON)
endif()


if ($ENV{VBUILD_UNIT_TESTS} MATCHES "true")
    foreach(testSrc ${TEST_SRCS})

        # Extract the filename without an extension (NAME_WE)
        get_filename_component(testName ${testSrc} NAME_WE)

        add_executable(${testName} "${testSrc}" "${SUPPORT_SRCS}")
        add_dependencies(${testName} opentdfstatic)

        if (CMAKE_VALGRIND_FOUND)
            add_test(NAME ${testName} COMMAND valgrind --error-exitcode=3 --leak-check=full $<TARGET_FILE:${testName}>)
        else()
            add_test(NAME ${testName} COMMAND $<TARGET_FILE:${testName}>)
        endif()
        if(DEFINED ENV{VBUILD_ADD_RPI_FLAGS})
          if($ENV{VBUILD_ADD_RPI_FLAGS} MATCHES "true")
            set_target_properties(${testName} PROPERTIES LINK_FLAGS "-mfloat-abi=hard -mfpu=vfpv2")
          endif()
        endif()
    endforeach(testSrc)
endif()

# Uncomment to generate debug symbols
# set(CMAKE_BUILD_TYPE Debug)

# Copy the data folder, some tests need them for sample files.
set(DATA_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/data")
file(COPY ${DATA_SOURCE_DIR} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
